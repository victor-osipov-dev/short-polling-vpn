//! Native Windows VPN mode: a Wintun adapter bridged to a user-space TCP/IP
//! stack. TCP streams are mapped onto tunnel sessions; DNS is resolved by a
//! small built-in proxy so domain-based split routing still works.

#![cfg(windows)]

use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::routing::Decision;
use crate::tunnel::{Down, Session, Tunnel};

const TUN_NAME: &str = "SPVPN";
const TUN_TYPE: &str = "SPVPN";
const ADAPTER_GUID: u128 = 0x5350_5650_4e00_4a31_9e6d_5f0d_9b3c_7a11;
const WINTUN_DLL: &[u8] = include_bytes!("../resources/wintun.dll");
const ROUTE_NO_WINDOW: u32 = 0x0800_0000;
/// Upper bound on concurrent TUN connections; protects against a runaway
/// application opening sockets faster than the tunnel can carry them.
const MAX_TUN_CONNECTIONS: usize = 512;
const DNS_TTL_MIN: u32 = 30;
const DNS_TTL_MAX: u32 = 3600;
const DNS_DEFAULT_TTL: u32 = 300;

#[derive(Clone, Debug)]
pub struct TunConfig {
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub dns: Ipv4Addr,
    pub mtu: usize,
    pub dns_upstream: SocketAddr,
    /// IPv4 prefixes kept on the physical route (direct split routing, local
    /// resources, custom exclusions).
    pub exclusions: Vec<ipnet::Ipv4Net>,
}

impl TunConfig {
    pub fn from_settings(settings: &crate::store::Settings) -> Result<Self> {
        let address = settings
            .tun_address
            .parse()
            .unwrap_or(Ipv4Addr::new(10, 7, 0, 1));
        let netmask = settings
            .tun_netmask
            .parse()
            .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));
        let dns = settings
            .tun_dns
            .parse()
            .unwrap_or(Ipv4Addr::new(10, 7, 0, 53));
        let dns_upstream = settings
            .tun_dns_upstream
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([1, 1, 1, 1], 53)));
        let mut exclusions = Vec::new();
        for value in &settings.tun_exclude {
            let value = value.trim();
            if value.is_empty() {
                continue;
            }
            if let Ok(ip) = value.parse::<Ipv4Addr>() {
                exclusions.push(ipnet::Ipv4Net::new(ip, 32).expect("valid /32"));
            } else if let Ok(net) = value.parse::<ipnet::Ipv4Net>() {
                exclusions.push(net);
            } else {
                tracing::warn!("ignoring invalid TUN exclusion {value:?}");
            }
        }
        Ok(Self {
            address,
            netmask,
            dns,
            mtu: settings.tun_mtu.clamp(576, 9000),
            dns_upstream,
            exclusions,
        })
    }
}

#[derive(Default)]
pub struct DomainCache {
    inner: Mutex<HashMap<IpAddr, (String, Instant)>>,
}

impl DomainCache {
    pub fn host_for(&self, ip: IpAddr) -> Option<String> {
        let mut inner = self.inner.lock();
        match inner.get(&ip) {
            Some((name, expires)) if *expires > Instant::now() => Some(name.clone()),
            Some(_) => {
                inner.remove(&ip);
                None
            }
            None => None,
        }
    }

    fn insert(&self, ip: IpAddr, name: String, ttl: u32) {
        let ttl = ttl.clamp(DNS_TTL_MIN, DNS_TTL_MAX);
        let mut inner = self.inner.lock();
        // Keep the map bounded even when a resolver returns huge answer sets;
        // expired entries are cheap to drop here.
        if inner.len() > 4096 {
            let now = Instant::now();
            inner.retain(|_, (_, expires)| *expires > now);
        }
        inner.insert(ip, (name, Instant::now() + Duration::from_secs(ttl as u64)));
    }
}

struct Routes {
    /// (destination, mask) pairs. The mask is mandatory: `route delete 0.0.0.0`
    /// would remove every default route, including the physical one.
    added: Vec<(String, String)>,
    v6_added: Vec<String>,
    if_index: u32,
}

impl Routes {
    fn new(if_index: u32) -> Self {
        Self {
            added: Vec::new(),
            v6_added: Vec::new(),
            if_index,
        }
    }

    fn add(&mut self, target: &str, mask: &str, gateway: &str, if_index: Option<u32>) -> Result<()> {
        let mut args = vec![
            "add".to_owned(),
            target.to_owned(),
            "mask".to_owned(),
            mask.to_owned(),
            gateway.to_owned(),
        ];
        if let Some(index) = if_index {
            args.push("if".to_owned());
            args.push(index.to_string());
        }
        args.push("metric".to_owned());
        args.push("1".to_owned());
        run_route(&args)?;
        self.added.push((target.to_owned(), mask.to_owned()));
        Ok(())
    }

    /// Adds one of the two `/1` routes that override the physical default
    /// route. A stale copy from a crashed session is removed first so `add`
    /// does not fail with "object already exists".
    fn add_default(&mut self, target: &str, mask: &str, gateway: &str) -> Result<()> {
        let _ = run_route(&[
            "delete".to_owned(),
            target.to_owned(),
            "mask".to_owned(),
            mask.to_owned(),
        ]);
        self.add(target, mask, gateway, Some(self.if_index))
    }

    /// IPv6 has no relay support, so its traffic is routed into the TUN where
    /// it is dropped instead of leaking through the physical adapter. Failure
    /// is not fatal (IPv6 may already be disabled on the adapter).
    fn add_v6_blackhole(&mut self, prefix: &str) {
        let index = self.if_index.to_string();
        if let Err(err) = run_netsh(&[
            "interface",
            "ipv6",
            "add",
            "route",
            prefix,
            &format!("interface={index}"),
            "metric=1",
            "store=active",
        ]) {
            tracing::warn!("cannot add IPv6 route {prefix}: {err:#}");
            return;
        }
        self.v6_added.push(prefix.to_owned());
    }

    fn cleanup(&mut self) {
        for (target, mask) in self.added.drain(..) {
            let _ = run_route(&["delete".to_owned(), target, "mask".to_owned(), mask]);
        }
        let index = self.if_index.to_string();
        for prefix in self.v6_added.drain(..) {
            let _ = run_netsh(&[
                "interface",
                "ipv6",
                "delete",
                "route",
                &prefix,
                &format!("interface={index}"),
                "store=active",
            ]);
        }
    }
}

impl Drop for Routes {
    fn drop(&mut self) {
        // Safety net for failures after routes were installed, or for a
        // runtime dropped without `stop()`.
        self.cleanup();
    }
}

pub struct TunRuntime {
    pub interface: String,
    pub address: Ipv4Addr,
    pub adapter_index: u32,
    session: Arc<wintun::Session>,
    adapter: Arc<wintun::Adapter>,
    tasks: Vec<JoinHandle<()>>,
    reader: Option<std::thread::JoinHandle<()>>,
    routes: Mutex<Routes>,
    direct_routes: Arc<Mutex<HashSet<Ipv4Addr>>>,
}

impl TunRuntime {
    pub async fn start(
        tunnel: Arc<Tunnel>,
        config: TunConfig,
        cache: Arc<DomainCache>,
        state_dir: &Path,
    ) -> Result<Self> {
        if !is_elevated() {
            anyhow::bail!("VPN mode requires Administrator rights");
        }
        let dll = ensure_wintun(state_dir)?;
        let wintun = unsafe { wintun::load_from_path(&dll) }
            .with_context(|| format!("cannot load {}", dll.display()))?;
        let adapter = match wintun::Adapter::open(&wintun, TUN_NAME) {
            Ok(adapter) => adapter,
            Err(_) => wintun::Adapter::create(&wintun, TUN_NAME, TUN_TYPE, Some(ADAPTER_GUID))
                .context("cannot create Wintun adapter (run as Administrator)")?,
        };
        adapter
            .set_name(TUN_NAME)
            .context("cannot rename Wintun adapter")?;
        adapter
            .set_address(config.address)
            .context("cannot set TUN address")?;
        adapter
            .set_netmask(config.netmask)
            .context("cannot set TUN netmask")?;
        adapter
            .set_gateway(Some(config.address))
            .context("cannot set TUN gateway")?;
        // Only the IPv4 resolver is advertised: the stack has no IPv6 DNS
        // listener, and a dead IPv6 server would delay every lookup.
        adapter
            .set_dns_servers(&[IpAddr::V4(config.dns)])
            .context("cannot set TUN DNS")?;
        adapter
            .set_mtu(config.mtu)
            .context("cannot set TUN MTU")?;
        let index = adapter
            .get_adapter_index()
            .context("cannot query TUN interface index")?;
        let session = Arc::new(
            adapter
                .start_session(wintun::MAX_RING_CAPACITY)
                .context("cannot start Wintun session")?,
        );

        let (stack, runner, udp, tcp) = netstack_smoltcp::StackBuilder::default()
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .mtu(config.mtu)
            .build()
            .context("cannot build user-space TCP/IP stack")?;
        let runner = runner.context("netstack runner is missing")?;
        let tcp = tcp.context("netstack TCP listener is missing")?;
        let udp = udp.context("netstack UDP socket is missing")?;

        let gateway = physical_gateway(config.address);
        let mut routes = Routes::new(index);
        let gateway_label = gateway
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| "0.0.0.0".into());
        // Two /1 routes override the physical default route without deleting
        // it, which makes cleanup safe even after a crash.
        routes
            .add_default("0.0.0.0", "128.0.0.0", &config.address.to_string())
            .context("cannot add TUN route 0.0.0.0/1")?;
        routes
            .add_default("128.0.0.0", "128.0.0.0", &config.address.to_string())
            .context("cannot add TUN route 128.0.0.0/1")?;
        // No IPv6 relay: keep IPv6 inside the tunnel instead of leaking it
        // past the physical adapter.
        routes.add_v6_blackhole("::/1");
        routes.add_v6_blackhole("8000::/1");
        if gateway.is_some() {
            let mut pin = |target: &str, mask: &str, what: &str| {
                if let Err(err) = routes.add(target, mask, &gateway_label, None) {
                    tracing::warn!("cannot route {what} {target} via {gateway_label}: {err:#}");
                }
            };
            for ip in tunnel.server_ips() {
                if let IpAddr::V4(ip) = ip {
                    pin(&ip.to_string(), "255.255.255.255", "entry server");
                }
            }
            if let IpAddr::V4(ip) = config.dns_upstream.ip() {
                pin(&ip.to_string(), "255.255.255.255", "DNS upstream");
            }
            for net in &config.exclusions {
                pin(
                    &net.network().to_string(),
                    &net.netmask().to_string(),
                    "exclusion",
                );
            }
        } else {
            tracing::warn!("no physical IPv4 gateway found; entry servers may loop through the TUN");
        }

        let running = Arc::new(AtomicBool::new(true));
        let (tun_tx, mut tun_rx) = mpsc::channel::<Vec<u8>>(256);

        // Blocking Wintun reader on its own OS thread.
        let reader_session = session.clone();
        let reader_running = running.clone();
        let reader = std::thread::Builder::new()
            .name("spvpn-tun-read".into())
            .spawn(move || {
                while reader_running.load(Ordering::Acquire) {
                    match reader_session.receive_blocking() {
                        Ok(packet) => {
                            let data = packet.bytes().to_vec();
                            if tun_tx.blocking_send(data).is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            })
            .context("cannot spawn Wintun reader")?;

        let (mut stack_sink, mut stack_stream) = stack.split();

        // TUN -> netstack.
        let tunnel_packets = tokio::spawn(async move {
            while let Some(packet) = tun_rx.recv().await {
                if stack_sink.send(packet).await.is_err() {
                    break;
                }
            }
        });

        // netstack -> TUN.
        let write_session = session.clone();
        let write_running = running.clone();
        let writer = tokio::spawn(async move {
            loop {
                let packet = match stack_stream.next().await {
                    Some(Ok(packet)) => packet,
                    Some(Err(err)) => {
                        tracing::warn!("netstack: {err}");
                        break;
                    }
                    None => break,
                };
                if !write_running.load(Ordering::Acquire) {
                    break;
                }
                let len = packet.len();
                if len > u16::MAX as usize || len == 0 {
                    continue;
                }
                match write_session.allocate_send_packet(len as u16) {
                    Ok(mut out) => {
                        out.bytes_mut().copy_from_slice(&packet);
                        write_session.send_packet(out);
                    }
                    Err(err) => tracing::warn!("TUN send: {err}"),
                }
            }
        });
        let stack_pump = tokio::spawn(async move {
            if let Err(err) = runner.await {
                tracing::warn!("netstack runner: {err}");
            }
        });

        let direct_routes = Arc::new(Mutex::new(HashSet::new()));
        let listener_task = tokio::spawn(accept_loop(
            tcp,
            tunnel.clone(),
            cache.clone(),
            running.clone(),
            config.dns,
            config.dns_upstream,
            gateway,
            direct_routes.clone(),
        ));
        let dns_task = tokio::spawn(udp_loop(
            udp,
            cache,
            config.dns_upstream,
            running.clone(),
        ));

        tracing::info!(
            "TUN up: {}/{} mtu {} dns {} via {} (if {index})",
            config.address,
            config.netmask,
            config.mtu,
            config.dns,
            gateway_label,
        );

        Ok(Self {
            interface: TUN_NAME.into(),
            address: config.address,
            adapter_index: index,
            session,
            adapter,
            tasks: vec![tunnel_packets, writer, stack_pump, listener_task, dns_task],
            reader: Some(reader),
            routes: Mutex::new(routes),
            direct_routes,
        })
    }

    pub async fn stop(mut self) {
        for ip in self.direct_routes.lock().drain() {
            let _ = run_route(&[
                "delete".to_owned(),
                ip.to_string(),
                "mask".to_owned(),
                "255.255.255.255".to_owned(),
            ]);
        }
        self.routes.lock().cleanup();
        let _ = self.session.shutdown();
        for task in self.tasks.drain(..) {
            task.abort();
        }
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        // Do not leave a default gateway behind on the (persistent) adapter.
        let _ = self.adapter.set_gateway(None);
        drop(self.session);
        drop(self.adapter);
        tracing::info!("TUN stopped");
    }
}

#[allow(clippy::too_many_arguments)]
async fn accept_loop(
    mut listener: netstack_smoltcp::TcpListener,
    tunnel: Arc<Tunnel>,
    cache: Arc<DomainCache>,
    running: Arc<AtomicBool>,
    dns: Ipv4Addr,
    dns_upstream: SocketAddr,
    gateway: Option<Ipv4Addr>,
    direct_routes: Arc<Mutex<HashSet<Ipv4Addr>>>,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(MAX_TUN_CONNECTIONS));
    while running.load(Ordering::Acquire) {
        let Some((stream, _local, remote)) = listener.next().await else {
            break;
        };
        if remote.is_ipv6() {
            // IPv6 is routed into the TUN only to keep it from leaking; there
            // is no IPv6 relay, so reset the connection immediately.
            tracing::debug!("TUN: dropping IPv6 connection to {remote}");
            drop(stream);
            continue;
        }
        let permit = match slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!("TUN: connection limit reached, dropping {remote}");
                drop(stream);
                continue;
            }
        };
        let tunnel = tunnel.clone();
        let cache = cache.clone();
        let direct_routes = direct_routes.clone();
        tokio::spawn(async move {
            let _permit = permit;
            // Only the address we advertised as DNS is treated as DNS; port 53
            // may legitimately host other services.
            if remote.port() == 53 && remote.ip() == IpAddr::V4(dns) {
                if let Err(err) = dns_tcp(stream, dns_upstream, &cache).await {
                    tracing::debug!("DNS/TCP: {err:#}");
                }
                return;
            }
            let host = cache
                .host_for(remote.ip())
                .unwrap_or_else(|| remote.ip().to_string());
            // Entry servers must never be tunnelled: their HTTP polls carry the
            // tunnel itself. Pinning can fail, so enforce it here as well.
            let is_entry = tunnel.server_ips().iter().any(|ip| *ip == remote.ip());
            let decision = if is_entry {
                Decision::Direct
            } else {
                tunnel.route(&host)
            };
            match decision {
                Decision::Direct => {
                    if let IpAddr::V4(ip) = remote.ip() {
                        // The TUN owns the default route. Pin direct
                        // destinations to the physical gateway, otherwise the
                        // kernel would feed this connection back into us.
                        if let Some(gateway) = gateway {
                            let mut seen = direct_routes.lock();
                            if seen.insert(ip) {
                                let target = ip.to_string();
                                let gw = gateway.to_string();
                                if let Err(err) = run_route(&[
                                    "add".to_owned(),
                                    target,
                                    "mask".to_owned(),
                                    "255.255.255.255".to_owned(),
                                    gw,
                                    "metric".to_owned(),
                                    "1".to_owned(),
                                ]) {
                                    // The route may already exist from an
                                    // earlier session; the direct connect
                                    // below will still succeed.
                                    tracing::debug!("direct route {ip}: {err:#}");
                                }
                            }
                        }
                    }
                    if let Err(err) = direct_connection(stream, remote).await {
                        tracing::debug!("direct {remote}: {err:#}");
                    }
                }
                Decision::Tunnel {
                    entry,
                    chain,
                    category,
                } => {
                    let decision = Decision::Tunnel {
                        entry,
                        chain,
                        category,
                    };
                    match tunnel.open(host.clone(), remote.port(), decision).await {
                        Ok((session, down_rx)) => {
                            tracing::debug!(
                                "TUN {}:{} -> {} [{}]",
                                host,
                                remote.port(),
                                remote,
                                category.as_str()
                            );
                            relay(stream, session, down_rx, tunnel.clone()).await;
                        }
                        Err(err) => {
                            tracing::warn!("TUN open {}:{}: {err:#}", host, remote.port())
                        }
                    }
                }
                Decision::Error(reason) => {
                    tracing::warn!("TUN {host}:{remote}: {reason}");
                }
            }
        });
    }
}

async fn direct_connection(
    stream: netstack_smoltcp::TcpStream,
    remote: SocketAddr,
) -> Result<()> {
    let upstream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(remote),
    )
    .await
    .context("direct connect timed out")??;
    upstream.set_nodelay(true).ok();
    let (mut cr, mut cw) = tokio::io::split(stream);
    let (mut ur, mut uw) = upstream.into_split();
    let c2u = async {
        let _ = tokio::io::copy(&mut cr, &mut uw).await;
        let _ = uw.shutdown().await;
    };
    let u2c = async {
        let _ = tokio::io::copy(&mut ur, &mut cw).await;
        let _ = cw.shutdown().await;
    };
    tokio::join!(c2u, u2c);
    Ok(())
}

async fn relay<S>(
    stream: S,
    session: Arc<Session>,
    mut down_rx: mpsc::Receiver<Down>,
    tunnel: Arc<Tunnel>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let sid = session.id;
    let (mut reader, mut writer) = tokio::io::split(stream);
    let reader_tunnel = tunnel.clone();
    let mut reader_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 32 * 1024];
        loop {
            match reader.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => session.push_outgoing(Bytes::copy_from_slice(&buf[..n])).await,
                Err(_) => break,
            }
        }
        reader_tunnel.local_closed(&session.id).await;
        session
    });
    let mut writer_task = tokio::spawn(async move {
        while let Some(msg) = down_rx.recv().await {
            match msg {
                Down::Data(data) => {
                    if writer.write_all(&data).await.is_err() {
                        return false;
                    }
                }
                Down::Fin => {
                    let _ = writer.shutdown().await;
                    return true;
                }
            }
        }
        false
    });
    tokio::select! {
        _ = &mut reader_task => {
            if tokio::time::timeout(Duration::from_secs(30), &mut writer_task).await.is_err() {
                writer_task.abort();
            }
        }
        _ = &mut writer_task => {
            reader_task.abort();
        }
    }
    tunnel.close(&sid);
}

async fn udp_loop(
    udp: netstack_smoltcp::UdpSocket,
    cache: Arc<DomainCache>,
    upstream: SocketAddr,
    running: Arc<AtomicBool>,
) {
    let (mut reader, writer) = udp.split();
    let writer = Arc::new(tokio::sync::Mutex::new(writer));
    while running.load(Ordering::Acquire) {
        let Some((payload, local, remote)) = reader.next().await else {
            break;
        };
        if remote.port() != 53 {
            // QUIC and other UDP protocols fall back to TCP.
            continue;
        }
        let cache = cache.clone();
        let writer = writer.clone();
        tokio::spawn(async move {
            match dns_query(&payload, upstream).await {
                Ok(response) => {
                    learn_dns(&response, &cache);
                    let mut guard = writer.lock().await;
                    let _ = guard.send((response, remote, local)).await;
                }
                Err(err) => tracing::debug!("DNS/UDP: {err:#}"),
            }
        });
    }
}

async fn dns_query(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let bind = if upstream.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    socket.connect(upstream).await?;
    let mut buf = vec![0u8; 4096];
    let mut last_err = None;
    for _ in 0..2 {
        socket.send(query).await?;
        match tokio::time::timeout(Duration::from_secs(4), socket.recv(&mut buf)).await {
            Ok(Ok(n)) => {
                let response = buf[..n].to_vec();
                if response.len() > 2 && response[2] & 0x02 != 0 {
                    return dns_tcp_query(query, upstream).await;
                }
                return Ok(response);
            }
            Ok(Err(err)) => last_err = Some(err),
            Err(_) => continue,
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("DNS timeout")))
}

async fn dns_tcp_query(query: &[u8], upstream: SocketAddr) -> Result<Vec<u8>> {
    let mut stream = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::net::TcpStream::connect(upstream),
    )
    .await
    .context("DNS/TCP connect timed out")??;
    let mut framed = Vec::with_capacity(query.len() + 2);
    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
    framed.extend_from_slice(query);
    tokio::time::timeout(Duration::from_secs(5), stream.write_all(&framed))
        .await
        .context("DNS/TCP write timed out")??;
    let mut len = [0u8; 2];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut len))
        .await
        .context("DNS/TCP read timed out")??;
    let size = u16::from_be_bytes(len) as usize;
    if size == 0 {
        anyhow::bail!("empty DNS response");
    }
    let mut response = vec![0u8; size];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut response))
        .await
        .context("DNS/TCP read timed out")??;
    Ok(response)
}

async fn dns_tcp(
    mut stream: netstack_smoltcp::TcpStream,
    upstream: SocketAddr,
    cache: &DomainCache,
) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async move {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len).await?;
        let size = u16::from_be_bytes(len) as usize;
        if size == 0 {
            anyhow::bail!("empty DNS query");
        }
        let mut query = vec![0u8; size];
        stream.read_exact(&mut query).await?;
        let response = dns_tcp_query(&query, upstream).await?;
        // DNS-over-TCP answers must teach the split-routing cache too.
        learn_dns(&response, cache);
        let mut framed = Vec::with_capacity(response.len() + 2);
        framed.extend_from_slice(&(response.len() as u16).to_be_bytes());
        framed.extend_from_slice(&response);
        stream.write_all(&framed).await?;
        stream.shutdown().await.ok();
        Ok(())
    })
    .await
    .context("DNS/TCP session timed out")?
}

fn learn_dns(packet: &[u8], cache: &DomainCache) {
    if packet.len() < 12 || packet[2] & 0x80 == 0 || packet[3] & 0x0f != 0 {
        // Not a successful response.
        return;
    }
    let Some((name, _)) = dns_question(packet) else {
        return;
    };
    let Some(qend) = question_end(packet) else {
        return;
    };
    let count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = qend;
    for _ in 0..count {
        let Some((_, next)) = dns_name(packet, offset) else {
            return;
        };
        offset = next;
        if offset + 10 > packet.len() {
            return;
        }
        let typ = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlen = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlen > packet.len() {
            return;
        }
        let rdata = &packet[offset..offset + rdlen];
        if typ == 1 && rdlen == 4 {
            cache.insert(
                IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])),
                name.clone(),
                if ttl == 0 { DNS_DEFAULT_TTL } else { ttl },
            );
        }
        offset += rdlen;
    }
}

fn dns_question(packet: &[u8]) -> Option<(String, usize)> {
    if packet.len() < 12 {
        return None;
    }
    let (name, offset) = dns_name(packet, 12)?;
    Some((name, offset))
}

fn question_end(packet: &[u8]) -> Option<usize> {
    if packet.len() < 12 {
        return None;
    }
    let (_, mut offset) = dns_name(packet, 12)?;
    offset += 4; // qtype + qclass
    if offset > packet.len() {
        None
    } else {
        Some(offset)
    }
}

fn dns_name(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end = start;
    for _ in 0..64 {
        let len = *packet.get(offset)?;
        if len == 0 {
            if !jumped {
                end = offset + 1;
            }
            return Some((labels.join("."), end));
        }
        if len & 0xC0 == 0xC0 {
            let ptr = ((len as usize & 0x3F) << 8) | *packet.get(offset + 1)? as usize;
            if !jumped {
                end = offset + 2;
            }
            offset = ptr;
            jumped = true;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let begin = offset + 1;
        let finish = begin + len as usize;
        let label = std::str::from_utf8(packet.get(begin..finish)?).ok()?;
        labels.push(label.to_owned());
        offset = finish;
    }
    None
}

fn physical_gateway(tun_address: Ipv4Addr) -> Option<Ipv4Addr> {
    wintun::get_active_network_interface_gateways()
        .ok()?
        .into_iter()
        .find_map(|ip| match ip {
            IpAddr::V4(ip) if !ip.is_unspecified() && ip != tun_address => Some(ip),
            _ => None,
        })
}

fn ensure_wintun(state_dir: &Path) -> Result<PathBuf> {
    let beside_exe = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|p| p.join("wintun.dll")));
    if let Some(path) = beside_exe.as_ref().filter(|p| p.exists()) {
        return Ok(path.clone());
    }
    std::fs::create_dir_all(state_dir)?;
    let path = state_dir.join("wintun.dll");
    let size_ok = std::fs::metadata(&path)
        .map(|m| m.len() as usize == WINTUN_DLL.len())
        .unwrap_or(false);
    if !size_ok {
        std::fs::write(&path, WINTUN_DLL)
            .with_context(|| format!("cannot extract {}", path.display()))?;
    }
    Ok(path)
}

fn run_route(args: &[String]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let mut command = std::process::Command::new("route.exe");
    command.args(args).creation_flags(ROUTE_NO_WINDOW);
    let output = command.output().context("cannot run route.exe")?;
    if output.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stderr);
    let text = text.trim();
    let text = if text.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        text.to_owned()
    };
    anyhow::bail!(
        "route.exe {} failed: {}",
        args.join(" "),
        if text.is_empty() { "unknown error" } else { &text }
    )
}

fn run_netsh(args: &[&str]) -> Result<()> {
    use std::os::windows::process::CommandExt;
    let mut command = std::process::Command::new("netsh");
    command.args(args).creation_flags(ROUTE_NO_WINDOW);
    let output = command.output().context("cannot run netsh")?;
    if output.status.success() {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&output.stderr);
    let text = text.trim();
    let text = if text.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        text.to_owned()
    };
    anyhow::bail!(
        "netsh {} failed: {}",
        args.join(" "),
        if text.is_empty() { "unknown error" } else { &text }
    )
}

pub fn is_elevated() -> bool {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = std::mem::zeroed();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation: TOKEN_ELEVATION = std::mem::zeroed();
        let mut size = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut _,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

/// Relaunches the current executable elevated (UAC prompt).
pub fn relaunch_elevated(args: &[String]) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

    let exe = std::env::current_exe()?;
    let exe_w: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
    let verb: Vec<u16> = "runas".encode_utf16().chain(Some(0)).collect();
    let params: Vec<u16> = args
        .iter()
        .map(|arg| {
            if arg.contains(' ') {
                format!("\"{arg}\"")
            } else {
                arg.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
        .encode_utf16()
        .chain(Some(0))
        .collect();
    unsafe {
        let result = ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe_w.as_ptr(),
            params.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        );
        if result as isize <= 32 {
            anyhow::bail!("UAC elevation was cancelled");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send_sync<T: Send + Sync>() {}
    is_send_sync::<DomainCache>();
    is_send_sync::<TunRuntime>();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Settings;

    fn push_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn response(flags: u16, answers: &[(u32, [u8; 4])]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[0x12, 0x34]);
        out.extend_from_slice(&flags.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        push_name(&mut out, "example.com");
        out.extend_from_slice(&1u16.to_be_bytes()); // A
        out.extend_from_slice(&1u16.to_be_bytes()); // IN
        for (ttl, ip) in answers {
            out.extend_from_slice(&[0xC0, 0x0C]); // pointer to the question name
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&1u16.to_be_bytes());
            out.extend_from_slice(&ttl.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
            out.extend_from_slice(ip);
        }
        out
    }

    #[test]
    fn learns_a_records_from_responses() {
        let cache = DomainCache::default();
        let packet = response(0x8180, &[(60, [93, 184, 216, 34]), (0, [1, 2, 3, 4])]);
        learn_dns(&packet, &cache);
        assert_eq!(
            cache.host_for("93.184.216.34".parse().unwrap()).as_deref(),
            Some("example.com")
        );
        // ttl == 0 is replaced with a sane default instead of expiring at once.
        assert!(cache.host_for("1.2.3.4".parse().unwrap()).is_some());
    }

    #[test]
    fn ignores_non_successful_dns_packets() {
        let cache = DomainCache::default();
        learn_dns(&response(0x8183, &[(60, [1, 2, 3, 4])]), &cache);
        learn_dns(&response(0x0100, &[(60, [1, 2, 3, 4])]), &cache);
        assert!(cache.host_for("1.2.3.4".parse().unwrap()).is_none());
    }

    #[test]
    fn domain_cache_entries_expire() {
        let cache = DomainCache::default();
        let ip: IpAddr = "5.6.7.8".parse().unwrap();
        cache
            .inner
            .lock()
            .insert(ip, ("old.example".into(), Instant::now() - Duration::from_secs(1)));
        assert!(cache.host_for(ip).is_none());
        cache.insert(ip, "new.example".into(), 60);
        assert_eq!(cache.host_for(ip).as_deref(), Some("new.example"));
    }

    #[test]
    fn exclusions_accept_prefixes_and_addresses() {
        let mut settings = Settings::default();
        settings.tun_exclude = vec![
            "10.0.0.0/8".into(),
            "192.168.1.5".into(),
            " 172.16.0.0/12 ".into(),
            "not-an-ip".into(),
        ];
        let config = TunConfig::from_settings(&settings).expect("valid config");
        assert_eq!(config.exclusions.len(), 3);
        assert_eq!(config.exclusions[0].prefix_len(), 8);
        assert_eq!(config.exclusions[1].prefix_len(), 32);
        assert_eq!(config.exclusions[2].prefix_len(), 12);
    }
}
