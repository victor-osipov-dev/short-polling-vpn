//! Async session manager used by the desktop UI. The UI thread only touches
//! `parking_lot` snapshots; all network work runs on a Tokio runtime.

use anyhow::{Context, Result};
use parking_lot::Mutex;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;

use crate::control::{self, ControlCtx, StateFile};
use crate::platform;
use crate::store::{ResolvedProfile, Store};
use crate::test_profile::{self, TestResult};
use crate::tun::DomainCache;
use crate::tunnel::{Status, Tunnel, TunnelHandle};

use crate::tun::{TunConfig, TunRuntime};

#[derive(Default, Clone)]
pub struct SharedState {
    pub busy: bool,
    pub running: bool,
    pub error: Option<String>,
    pub notice: Option<String>,
    pub socks: Option<String>,
    pub control: Option<String>,
    pub mode: String,
    pub tun_active: bool,
    pub status: Option<Status>,
    pub test_busy: bool,
    pub tests: Vec<TestResult>,
    pub exit_ip: String,
    pub store_revision: u64,
    pub tun_detail: Option<String>,
}

struct Running {
    tunnel: Arc<Tunnel>,
    handle: Option<TunnelHandle>,
    tun: Option<TunRuntime>,
    socks: String,
    mode: String,
    tasks: Vec<JoinHandle<()>>,
}

impl Running {
    async fn stop(mut self, dir: &Path) {
        if let Some(tun) = self.tun.take() {
            tun.stop().await;
        }
        for task in self.tasks.drain(..) {
            task.abort();
        }
        if let Some(handle) = self.handle.take() {
            handle.stop().await;
        }
        let _ = platform::disable_system_proxy(dir);
        control::clear_state(dir);
        tracing::info!("session stopped");
    }
}

pub struct Backend {
    rt: tokio::runtime::Runtime,
    dir: PathBuf,
    shared: Arc<Mutex<SharedState>>,
    running: Arc<Mutex<Option<Running>>>,
    cache: Arc<DomainCache>,
}

impl Backend {
    pub fn new(dir: &Path) -> Result<Arc<Self>> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .thread_name("spvpn-ui")
            .build()
            .context("cannot start async runtime")?;
        Ok(Arc::new(Self {
            rt,
            dir: dir.to_owned(),
            shared: Arc::new(Mutex::new(SharedState::default())),
            running: Arc::new(Mutex::new(None)),
            cache: Arc::new(DomainCache::default()),
        }))
    }

    pub fn shared(&self) -> Arc<Mutex<SharedState>> {
        self.shared.clone()
    }

    pub fn refresh(&self) {
        let snapshot = self
            .running
            .lock()
            .as_ref()
            .map(|run| (run.tunnel.snapshot(), run.socks.clone(), run.mode.clone(), run.tun.is_some()));
        let mut shared = self.shared.lock();
        if let Some((status, socks, mode, tun)) = snapshot {
            shared.running = true;
            shared.status = Some(status);
            shared.socks = Some(socks);
            shared.mode = mode;
            shared.tun_active = tun;
        } else {
            shared.running = false;
            shared.status = None;
            shared.tun_active = false;
        }
    }

    pub fn connect(&self, resolved: ResolvedProfile) -> bool {
        {
            let mut shared = self.shared.lock();
            if shared.busy || shared.running {
                return false;
            }
            shared.busy = true;
            shared.error = None;
            shared.notice = None;
        }
        if resolved.mode.eq_ignore_ascii_case("vpn") && !platform::is_elevated() {
            let mut shared = self.shared.lock();
            shared.busy = false;
            shared.error = Some("vpn_needs_admin".into());
            return false;
        }

        let shared = self.shared.clone();
        let running = self.running.clone();
        let cache = self.cache.clone();
        let dir = self.dir.clone();
        self.rt.spawn(async move {
            let result = start_session(&dir, resolved, cache, shared.clone(), running.clone()).await;
            let mut state = shared.lock();
            state.busy = false;
            match result {
                Ok(run) => {
                    state.notice = Some("connected".into());
                    *running.lock() = Some(run);
                }
                Err(err) => {
                    state.error = Some(format!("{err:#}"));
                    tracing::error!("connect failed: {err:#}");
                }
            }
        });
        true
    }

    pub fn disconnect(&self) -> bool {
        let mut run = self.running.lock().take();
        if run.is_none() {
            return false;
        }
        {
            let mut shared = self.shared.lock();
            shared.busy = true;
            shared.error = None;
        }
        let shared = self.shared.clone();
        let dir = self.dir.clone();
        self.rt.spawn(async move {
            if let Some(run) = run.take() {
                run.stop(&dir).await;
            }
            let mut state = shared.lock();
            state.busy = false;
            state.running = false;
            state.status = None;
            state.socks = None;
            state.tun_active = false;
            state.notice = Some("disconnected".into());
        });
        true
    }

    pub fn disconnect_blocking(&self) {
        if let Some(run) = self.running.lock().take() {
            let dir = self.dir.clone();
            let _ = self.rt.block_on(async move { run.stop(&dir).await });
        }
    }

    pub fn tunnel(&self) -> Option<Arc<Tunnel>> {
        self.running
            .lock()
            .as_ref()
            .map(|run| run.tunnel.clone())
    }

    pub fn clear_url_errors(&self) {
        if let Some(tunnel) = self.tunnel() {
            tunnel.clear_failures();
        }
    }

    pub fn test_profiles(&self, profiles: Vec<ResolvedProfile>, target: String) -> bool {
        if profiles.is_empty() {
            return false;
        }
        {
            let mut shared = self.shared.lock();
            if shared.test_busy {
                return false;
            }
            shared.test_busy = true;
            shared.tests.clear();
        }
        let shared = self.shared.clone();
        let cache = self.dir.join("cache");
        self.rt.spawn(async move {
            let _results = test_profile::test_many_stream(
                profiles,
                cache,
                target,
                Duration::from_secs(20),
                2,
                |result| {
                    let mut state = shared.lock();
                    if result.ok && state.exit_ip.is_empty() {
                        state.exit_ip = result.exit_ip.clone();
                    }
                    state.tests.push(result);
                },
            )
            .await;
            shared.lock().test_busy = false;
        });
        true
    }

    pub fn add_subscription(&self, source: String, name: Option<String>) {
        let dir = self.dir.clone();
        let shared = self.shared.clone();
        {
            let mut state = shared.lock();
            if state.busy {
                return;
            }
            state.busy = true;
            state.error = None;
        }
        self.rt.spawn(async move {
            let result = async {
                let mut store = Store::load(&dir)?;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(25))
                    .build()?;
                let id = crate::subscription::add(&mut store, &source, name, &client).await?;
                store.save(&dir)?;
                Ok::<_, anyhow::Error>(id)
            }
            .await;
            let mut state = shared.lock();
            state.busy = false;
            match result {
                Ok(_) => {
                    state.notice = Some("subscription_added".into());
                    state.store_revision += 1;
                }
                Err(err) => state.error = Some(format!("{err:#}")),
            }
        });
    }

    pub fn refresh_subscriptions(&self) {
        let dir = self.dir.clone();
        let shared = self.shared.clone();
        {
            let mut state = shared.lock();
            if state.busy {
                return;
            }
            state.busy = true;
            state.error = None;
        }
        self.rt.spawn(async move {
            let result = async {
                let mut store = Store::load(&dir)?;
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(25))
                    .build()?;
                let count = crate::subscription::refresh(&mut store, None, &client).await?;
                store.save(&dir)?;
                Ok::<_, anyhow::Error>(count)
            }
            .await;
            let mut state = shared.lock();
            state.busy = false;
            match result {
                Ok(count) => {
                    state.notice = Some(format!("refreshed:{count}"));
                    state.store_revision += 1;
                }
                Err(err) => state.error = Some(format!("{err:#}")),
            }
        });
    }

    pub fn take_notice(&self) -> Option<String> {
        self.shared.lock().notice.take()
    }
}

async fn start_session(
    dir: &Path,
    resolved: ResolvedProfile,
    cache: Arc<DomainCache>,
    shared: Arc<Mutex<SharedState>>,
    running: Arc<Mutex<Option<Running>>>,
) -> Result<Running> {
    let mode = resolved.mode.clone();
    let settings = resolved.settings.clone();
    let tun_config = if mode.eq_ignore_ascii_case("vpn") {
        Some(TunConfig::from_settings(&settings)?)
    } else {
        None
    };

    let tunnel = Tunnel::new(resolved, &dir.join("cache")).await?;
    let handle = tunnel.start();

    let socks_listener = bind_listener(&settings.socks_listen, "SOCKS5").await?;
    let socks = socks_listener.local_addr()?.to_string();
    let socks_task = tokio::spawn(crate::socks::serve_listener(socks_listener, tunnel.clone()));

    let control_listener = bind_listener(&settings.control_listen, "control").await?;
    let control_addr = control_listener.local_addr()?.to_string();
    let shutdown = Arc::new(Notify::new());
    let stopping = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ctx = ControlCtx {
        tunnel: tunnel.clone(),
        socks: socks.clone(),
        shutdown,
        stopping,
    };
    let control_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let control_label = control_addr.clone();
    let control_task = tokio::spawn(async move {
        let _ = control::serve_on(control_listener, &control_label, ctx, control_running).await;
    });

    let mut tun = None;
    if let Some(config) = tun_config {
        {
            let mut state = shared.lock();
            state.tun_detail = Some(format!(
                "{} / {}  dns {}",
                config.address, config.netmask, config.dns
            ));
        }
        match TunRuntime::start(tunnel.clone(), config, cache.clone(), dir).await {
            Ok(runtime) => {
                tunnel.set_mode("vpn");
                tun = Some(runtime);
            }
            Err(err) => {
                socks_task.abort();
                control_task.abort();
                handle.stop().await;
                let _ = platform::disable_system_proxy(dir);
                return Err(err.context("cannot start VPN mode"));
            }
        }
    }

    if mode.eq_ignore_ascii_case("vpn") {
        let _ = platform::disable_system_proxy(dir);
    } else if settings.system_proxy {
        if let Err(err) = platform::enable_system_proxy(&socks, dir) {
            tracing::warn!("system proxy: {err:#}");
        }
    }

    let state = StateFile {
        pid: std::process::id(),
        socks: socks.clone(),
        control: control_addr.clone(),
        profile: tunnel.profile_name.clone(),
        started_at: crate::subscription::now_secs(),
    };
    control::write_state(dir, &state)?;
    {
        let mut s = shared.lock();
        s.socks = Some(socks.clone());
        s.control = Some(control_addr.clone());
        s.mode = mode.clone();
    }
    tracing::info!(
        "GUI session: mode={mode} socks={socks} control={control_addr} tun={}",
        tun.is_some()
    );
    drop(running);
    Ok(Running {
        tunnel,
        handle: Some(handle),
        tun,
        socks,
        mode,
        tasks: vec![socks_task, control_task],
    })
}

async fn bind_listener(addr: &str, label: &str) -> Result<TcpListener> {
    let parsed: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid {label} address {addr:?}"))?;
    match TcpListener::bind(parsed).await {
        Ok(listener) => return Ok(listener),
        Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {
            for offset in 1..=20u16 {
                let Some(port) = parsed.port().checked_add(offset) else {
                    break;
                };
                let candidate = std::net::SocketAddr::new(parsed.ip(), port);
                if let Ok(listener) = TcpListener::bind(candidate).await {
                    return Ok(listener);
                }
            }
            anyhow::bail!("{label} port {} is busy", parsed.port())
        }
        Err(err) => Err(err).with_context(|| format!("cannot bind {label} on {addr}")),
    }
}
