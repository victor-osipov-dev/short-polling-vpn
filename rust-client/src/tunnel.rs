//! High-performance tunnel core: session multiplexing, per-URL poll workers,
//! quarantine, adaptive polling and stream-response parsing.

use anyhow::{Context, Result};
use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use parking_lot::Mutex;
use rand::Rng;
use reqwest::header::{HeaderMap, HeaderValue, CONTENT_TYPE, DATE};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Notify};
use tokio::task::JoinHandle;

use crate::cdn::random_cdn_path;
use crate::crypto::{b64u_encode, decrypt, encrypt, sign, Keys};
use crate::frame::{
    pack_frames, pad_frames, unpack_frames, Frame, FLAG_DATA, FLAG_DNS, FLAG_FIN,
    PROTO_VERSION, RESP_STREAM_MAGIC, SESSION_ID_LEN,
};
use crate::routing::{Decision, Router};
use crate::store::ResolvedProfile;

const USER_AGENT: &str =
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/131.0.0.0 Safari/537.36";
const HEALTH_INTERVAL: Duration = Duration::from_secs(1);
const IDLE_HEALTH_INTERVAL: Duration = Duration::from_secs(5);
const MAX_OUTBOX: usize = 4 * 1024 * 1024;
const REMOVE_AFTER_FIN: Duration = Duration::from_secs(5);
/// Retries for polls whose TCP connection never came up. The entry nodes
/// occasionally drop SYNs, and replaying the poll is safe because nothing
/// reached the server yet.
const POLL_CONNECT_RETRIES: u32 = 3;

#[derive(Clone, Debug)]
pub enum Down {
    Data(Bytes),
    Fin,
}

pub struct Stats {
    pub started: Instant,
    pub polls: AtomicU64,
    pub poll_ok: AtomicU64,
    pub poll_failed: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub opened: AtomicU64,
    pub closed: AtomicU64,
    pub last_poll_ms: AtomicU64,
    pub last_error: Mutex<String>,
}

impl Stats {
    fn new() -> Self {
        Self {
            started: Instant::now(),
            polls: AtomicU64::new(0),
            poll_ok: AtomicU64::new(0),
            poll_failed: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            opened: AtomicU64::new(0),
            closed: AtomicU64::new(0),
            last_poll_ms: AtomicU64::new(0),
            last_error: Mutex::new(String::new()),
        }
    }
}

struct Outbox {
    queue: VecDeque<Bytes>,
    queued: usize,
}

pub struct Session {
    pub id: [u8; SESSION_ID_LEN],
    pub base: String,
    pub route: Vec<String>,
    seq: AtomicU32,
    pending_new: Mutex<Option<Frame>>,
    outbox: Mutex<Outbox>,
    notify: Notify,
    down_tx: mpsc::Sender<Down>,
    closed: AtomicBool,
    fin_sent: AtomicBool,
    remove_at: Mutex<Option<Instant>>,
    wake: Arc<Notify>,
    pub target: (String, u16),
}

impl Session {
    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Queues bytes for the next poll; applies backpressure instead of growing
    /// memory without bound.
    pub async fn push_outgoing(&self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        let len = data.len();
        loop {
            {
                let mut out = self.outbox.lock();
                if out.queued + len <= MAX_OUTBOX {
                    out.queued += len;
                    out.queue.push_back(data);
                    drop(out);
                    self.wake.notify_one();
                    return;
                }
            }
            self.notify.notified().await;
        }
    }

    fn take_outgoing(&self, max: usize) -> (Option<Bytes>, bool) {
        let mut out = self.outbox.lock();
        let Some(front) = out.queue.front_mut() else {
            return (None, false);
        };
        if front.len() <= max {
            let data = out.queue.pop_front().expect("non-empty");
            out.queued -= data.len();
            let more = !out.queue.is_empty();
            drop(out);
            self.notify.notify_waiters();
            (Some(data), more)
        } else {
            let data = front.split_to(max);
            out.queued -= data.len();
            drop(out);
            self.notify.notify_waiters();
            (Some(data), true)
        }
    }

    fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

pub struct Tunnel {
    pub stats: Arc<Stats>,
    pub profile_name: String,
    pub router: Router,
    pub client_id: [u8; SESSION_ID_LEN],
    keys: Keys,
    user_id: Option<String>,
    device_id: String,
    urls: Vec<String>,
    poll_path: String,
    poll_interval: Duration,
    poll_idle: Duration,
    poll_min: Duration,
    poll_jitter_ms: u64,
    max_chunk: usize,
    max_frames: usize,
    pad_polls: bool,
    host_header: Option<String>,
    fail_limit: u32,
    cooldown: Duration,
    idle_timeout: Option<Duration>,
    http: reqwest::Client,
    sessions: Mutex<HashMap<[u8; SESSION_ID_LEN], Arc<Session>>>,
    by_base: Mutex<HashMap<String, HashSet<[u8; SESSION_ID_LEN]>>>,
    failures: Mutex<HashMap<String, u32>>,
    cooldowns: Mutex<HashMap<String, Instant>>,
    time_offsets: Mutex<HashMap<String, i64>>,
    last_activity: Mutex<Instant>,
    running: AtomicBool,
    wake: Arc<Notify>,
    idle_logged: AtomicBool,
    mode: Mutex<String>,
    server_ips: Vec<IpAddr>,
}

impl Tunnel {
    pub async fn new(resolved: ResolvedProfile, cache_dir: &std::path::Path) -> Result<Arc<Self>> {
        let settings = &resolved.settings;
        // Pin entry-server addresses so tunnel bookkeeping never resolves
        // through the TUN adapter (which would recurse into the tunnel).
        let (http, server_ips) = build_client(settings, &resolved.urls).await?;
        if let Err(err) = crate::routing::refresh_rules(cache_dir, &resolved.split, &http).await {
            tracing::warn!("rules refresh failed: {err:#}");
        }
        let ruleset = crate::routing::Ruleset::load(cache_dir, &resolved.split);
        let router = Router::new(
            resolved.split.clone(),
            ruleset,
            resolved.nodes.clone(),
            resolved.routes.clone(),
            resolved.urls.clone(),
            &settings.selector,
        );
        let poll_interval = Duration::from_millis(settings.poll_interval_ms.max(5));
        let poll_idle = Duration::from_millis(settings.poll_idle_ms.max(5)).max(HEALTH_INTERVAL);
        let poll_min = Duration::from_millis(settings.poll_min_ms.max(5));
        let idle_timeout = settings.idle_timeout_s.filter(|s| *s > 0).map(Duration::from_secs);
        let tunnel = Arc::new(Self {
            stats: Arc::new(Stats::new()),
            profile_name: resolved.name,
            router,
            client_id: crate::crypto::random_id(),
            keys: resolved.keys,
            user_id: resolved.user_id,
            device_id: resolved.device_id,
            urls: resolved.urls,
            poll_path: settings.poll_path.clone(),
            poll_interval,
            poll_idle,
            poll_min,
            poll_jitter_ms: settings.poll_jitter_ms,
            max_chunk: settings.max_chunk_bytes.max(1024),
            max_frames: settings.max_frames_per_poll.max(1),
            pad_polls: settings.pad_polls,
            host_header: settings.host_header.clone().filter(|h| !h.trim().is_empty()),
            fail_limit: settings.url_fail_limit.max(1),
            cooldown: Duration::from_secs(settings.url_cooldown_s.max(1)),
            idle_timeout,
            http,
            sessions: Mutex::new(HashMap::new()),
            by_base: Mutex::new(HashMap::new()),
            failures: Mutex::new(HashMap::new()),
            cooldowns: Mutex::new(HashMap::new()),
            time_offsets: Mutex::new(HashMap::new()),
            last_activity: Mutex::new(Instant::now()),
            running: AtomicBool::new(false),
            wake: Arc::new(Notify::new()),
            idle_logged: AtomicBool::new(false),
            mode: Mutex::new(resolved.mode.clone()),
            server_ips,
        });
        tracing::info!(
            "tunnel ready: profile={:?} urls={} split={} user={}",
            tunnel.profile_name,
            tunnel.urls.len(),
            tunnel.router.split.enabled,
            tunnel.user_id.is_some()
        );
        Ok(tunnel)
    }

    pub fn urls(&self) -> &[String] {
        &self.urls
    }

    /// IPv4 addresses of the entry servers; TUN mode keeps these on the
    /// physical route so polls do not loop through the tunnel.
    pub fn server_ips(&self) -> &[IpAddr] {
        &self.server_ips
    }

    pub fn mode(&self) -> String {
        self.mode.lock().clone()
    }

    pub fn set_mode(&self, mode: &str) {
        *self.mode.lock() = mode.to_owned();
    }

    /// Clears quarantine/failure counters so every entry URL is tried again.
    pub fn clear_failures(&self) {
        self.failures.lock().clear();
        self.cooldowns.lock().clear();
        self.stats.last_error.lock().clear();
        self.wake.notify_waiters();
        tracing::info!("URL health counters cleared");
    }

    pub fn route(&self, host: &str) -> Decision {
        self.router.route_for(host, &self.available_urls())
    }

    fn available_urls(&self) -> HashSet<String> {
        let now = Instant::now();
        let mut cooldowns = self.cooldowns.lock();
        let mut failures = self.failures.lock();
        cooldowns.retain(|url, until| {
            if *until <= now {
                failures.remove(url);
                false
            } else {
                true
            }
        });
        drop(failures);
        drop(cooldowns);
        let cool = self.cooldowns.lock();
        self.urls
            .iter()
            .filter(|u| !cool.contains_key(*u))
            .cloned()
            .collect()
    }

    fn touch(&self) {
        *self.last_activity.lock() = Instant::now();
        if self.idle_logged.swap(false, Ordering::Relaxed) {
            tracing::info!("activity resumed");
        }
    }

    fn idle(&self) -> bool {
        match self.idle_timeout {
            Some(timeout) => self.last_activity.lock().elapsed() > timeout,
            None => false,
        }
    }

    pub async fn open(
        &self,
        host: String,
        port: u16,
        decision: Decision,
    ) -> Result<(Arc<Session>, mpsc::Receiver<Down>)> {
        let (entry, route) = match decision {
            Decision::Tunnel {
                entry, chain, ..
            } => (entry, chain),
            Decision::Direct => anyhow::bail!("direct connections are not tunnel sessions"),
            Decision::Error(reason) => anyhow::bail!("{reason}"),
        };
        let sid = crate::crypto::random_id();
        let (down_tx, down_rx) = mpsc::channel(256);
        let session = Arc::new(Session {
            id: sid,
            base: entry.clone(),
            route: route.clone(),
            seq: AtomicU32::new(0),
            pending_new: Mutex::new(None),
            outbox: Mutex::new(Outbox {
                queue: VecDeque::new(),
                queued: 0,
            }),
            notify: Notify::new(),
            down_tx,
            closed: AtomicBool::new(false),
            fin_sent: AtomicBool::new(false),
            remove_at: Mutex::new(None),
            wake: self.wake.clone(),
            target: (host.clone(), port),
        });
        *session.pending_new.lock() = Some(Frame::new_target(sid, session.next_seq(), &host, port)?);
        self.sessions.lock().insert(sid, session.clone());
        self.by_base
            .lock()
            .entry(entry)
            .or_default()
            .insert(sid);
        self.wake.notify_one();
        self.stats.opened.fetch_add(1, Ordering::Relaxed);
        self.touch();
        tracing::debug!(
            "session {} -> {}:{} via {} {:?}",
            hex8(&sid),
            host,
            port,
            session.base,
            route
        );
        Ok((session, down_rx))
    }

    pub fn close(&self, sid: &[u8; SESSION_ID_LEN]) {
        let session = self.sessions.lock().remove(sid);
        if let Some(session) = session {
            if let Some(set) = self.by_base.lock().get_mut(&session.base) {
                set.remove(sid);
            }
            let _ = session.down_tx.try_send(Down::Fin);
            session.mark_closed();
            self.stats.closed.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn mark_locally_closed(&self, sid: &[u8; SESSION_ID_LEN]) {
        if let Some(session) = self.sessions.lock().get(sid) {
            session.mark_closed();
        }
    }

    fn fail_base_sessions(&self, base: &str, reason: &str) {
        let sids: Vec<_> = self
            .by_base
            .lock()
            .get(base)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        if sids.is_empty() {
            return;
        }
        tracing::warn!("closing {} session(s) on {base} ({reason})", sids.len());
        for sid in sids {
            self.close(&sid);
        }
    }

    fn mark_success(&self, base: &str) {
        let mut failures = self.failures.lock();
        let was_bad = failures.remove(base).unwrap_or(0) > 0;
        drop(failures);
        let was_quarantined = self.cooldowns.lock().remove(base).is_some();
        if was_bad || was_quarantined {
            tracing::info!("URL recovered: {base}");
        }
    }

    fn mark_failure(&self, base: &str, reason: &str) -> bool {
        self.stats.poll_failed.fetch_add(1, Ordering::Relaxed);
        *self.stats.last_error.lock() = reason.to_owned();
        let mut failures = self.failures.lock();
        let count = failures.entry(base.to_owned()).or_insert(0);
        *count += 1;
        let count = *count;
        drop(failures);
        if count < self.fail_limit {
            return false;
        }
        let mut cooldowns = self.cooldowns.lock();
        if let std::collections::hash_map::Entry::Vacant(e) = cooldowns.entry(base.to_owned()) {
            e.insert(Instant::now() + self.cooldown);
            drop(cooldowns);
            tracing::warn!(
                "URL quarantined for {}s: {base}",
                self.cooldown.as_secs()
            );
            return true;
        }
        false
    }

    pub fn start(self: &Arc<Self>) -> TunnelHandle {
        self.running.store(true, Ordering::Release);
        *self.last_activity.lock() = Instant::now();
        let mut tasks = Vec::new();
        for base in self.urls.clone() {
            let tunnel = self.clone();
            tasks.push(tokio::spawn(async move { tunnel.worker(base).await }));
        }
        let tunnel = self.clone();
        tasks.push(tokio::spawn(async move { tunnel.reaper().await }));
        tracing::info!("tunnel started ({} poll workers)", self.urls.len());
        TunnelHandle {
            tunnel: self.clone(),
            tasks,
        }
    }

    async fn worker(self: Arc<Self>, base: String) {
        let mut last_data = Instant::now() - Duration::from_secs(5);
        while self.running.load(Ordering::Acquire) {
            let now = Instant::now();
            let cooldown = self.cooldowns.lock().get(&base).copied();
            if let Some(until) = cooldown {
                if until > now {
                    self.fail_base_sessions(&base, "URL quarantined");
                    let wait = (until - now).min(Duration::from_secs(2));
                    tokio::time::sleep(wait.max(Duration::from_millis(50))).await;
                    continue;
                }
                self.mark_success(&base);
            }
            if self.idle() {
                if !self.idle_logged.swap(true, Ordering::Relaxed) {
                    tracing::info!("idle timeout: pausing traffic polls");
                }
                // Keep a slow health check so the URL state stays fresh, but
                // resume immediately when the user opens a connection.
                tokio::select! {
                    _ = self.wake.notified() => {}
                    _ = tokio::time::sleep(IDLE_HEALTH_INTERVAL) => {}
                }
                continue;
            }

            let active = !self
                .by_base
                .lock()
                .get(&base)
                .map(|s| s.is_empty())
                .unwrap_or(true);
            let groups = self.collect(&base);
            let mut more = false;
            let mut got_data = false;
            for group in groups {
                more |= group.more;
                let had_frames = !group.frames.is_empty();
                let route = group.route;
                match self.poll(&base, &route, group.frames).await {
                    Ok(true) => {
                        self.stats.poll_ok.fetch_add(1, Ordering::Relaxed);
                        self.mark_success(&base);
                        got_data = true;
                        last_data = Instant::now();
                    }
                    Ok(false) => {
                        self.stats.poll_ok.fetch_add(1, Ordering::Relaxed);
                        self.mark_success(&base);
                    }
                    Err(err) => {
                        let reason = format!("{err:#}");
                        if had_frames {
                            tracing::warn!("poll {base} failed: {reason}");
                        } else {
                            tracing::debug!("health poll {base}: {reason}");
                        }
                        let quarantined = self.mark_failure(&base, &reason);
                        if had_frames {
                            self.fail_route_sessions(&base, &route, &reason);
                        }
                        if quarantined {
                            self.fail_base_sessions(&base, &reason);
                        }
                    }
                }
            }
            self.stats
                .last_poll_ms
                .store(epoch_millis(), Ordering::Relaxed);
            if more || got_data || last_data.elapsed() < Duration::from_millis(250) {
                // Data is flowing: poll again as fast as possible.
                tokio::task::yield_now().await;
                continue;
            }
            let mut delay = if active {
                self.poll_interval
            } else {
                self.poll_idle
            };
            delay = delay.max(self.poll_min);
            if self.poll_jitter_ms > 0 {
                let jitter = rand::thread_rng()
                    .gen_range(0..=self.poll_jitter_ms.min(delay.as_millis() as u64 / 2 + 1));
                let signed = rand::thread_rng().gen_bool(0.5);
                let adjust = Duration::from_millis(jitter);
                delay = if signed && delay > adjust {
                    delay - adjust
                } else {
                    delay + adjust
                };
            }
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(delay.max(Duration::from_millis(5))) => {}
            }
            if !self.running.load(Ordering::Acquire) {
                break;
            }
        }
        tracing::debug!("poll worker stopped for {base}");
    }

    fn collect(&self, base: &str) -> Vec<Collected> {
        let sids: Vec<_> = self
            .by_base
            .lock()
            .get(base)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default();
        let mut groups: HashMap<Vec<String>, Collected> = HashMap::new();
        for sid in sids {
            let Some(session) = self.sessions.lock().get(&sid).cloned() else {
                continue;
            };
            let group = groups
                .entry(session.route.clone())
                .or_insert_with(|| Collected {
                    route: session.route.clone(),
                    frames: Vec::new(),
                    more: false,
                });
            if group.frames.len() >= self.max_frames {
                group.more = true;
                continue;
            }
            if let Some(new) = session.pending_new.lock().take() {
                group.frames.push(new);
                if group.frames.len() >= self.max_frames {
                    group.more = true;
                    continue;
                }
            }
            let (chunk, chunk_more) = session.take_outgoing(self.max_chunk);
            if let Some(chunk) = chunk {
                let frame = Frame::new(sid, session.next_seq(), FLAG_DATA, chunk.clone());
                self.stats
                    .tx_bytes
                    .fetch_add(chunk.len() as u64, Ordering::Relaxed);
                group.frames.push(frame);
                group.more |= chunk_more;
            }
            if session.is_closed()
                && session.outbox.lock().queue.is_empty()
                && !session.fin_sent.swap(true, Ordering::AcqRel)
            {
                group
                    .frames
                    .push(Frame::new(sid, session.next_seq(), FLAG_FIN, Bytes::new()));
                *session.remove_at.lock() = Some(Instant::now() + REMOVE_AFTER_FIN);
            }
            if group.frames.len() >= self.max_frames {
                group.more = true;
            }
        }
        groups.into_values().collect()
    }

    async fn poll(&self, base: &str, route: &[String], frames: Vec<Frame>) -> Result<bool> {
        let frames = if self.pad_polls {
            pad_frames(frames)
        } else {
            frames
        };
        // The route header is shared by the whole poll, so the worker groups
        // sessions by (entry URL, chain) before calling this function.
        let route_header = if route.len() > 1 {
            route.join(",")
        } else {
            String::new()
        };
        let sent_frames = frames.len();
        let sent_bytes = frames.iter().map(|f| f.payload.len()).sum::<usize>();
        let batch = pack_frames(&frames);
        let blob = encrypt(&self.keys.enc, &batch);
        let body = b64u_encode(&blob);

        let offset = *self.time_offsets.lock().get(base).unwrap_or(&0);
        let ts = (now_secs() + offset).to_string();
        let mut mac_data = Vec::with_capacity(
            self.client_id.len()
                + self.user_id.as_ref().map(|u| u.len()).unwrap_or(0)
                + self.device_id.len()
                + route_header.len()
                + ts.len()
                + blob.len(),
        );
        mac_data.extend_from_slice(&self.client_id);
        if let Some(user) = &self.user_id {
            mac_data.extend_from_slice(user.as_bytes());
            mac_data.extend_from_slice(self.device_id.as_bytes());
        }
        mac_data.extend_from_slice(route_header.as_bytes());
        mac_data.extend_from_slice(ts.as_bytes());
        mac_data.extend_from_slice(&blob);
        let mac = sign(&self.keys.hmac, &mac_data);

        let mut headers = HeaderMap::new();
        headers.insert("X-Cid", HeaderValue::from_str(&b64u_encode(&self.client_id))?);
        headers.insert("X-Mac", HeaderValue::from_str(&mac)?);
        headers.insert("X-Proto", HeaderValue::from_static(PROTO_VERSION));
        if let Some(user) = &self.user_id {
            headers.insert("X-User", HeaderValue::from_str(&user.to_uppercase())?);
            headers.insert(
                "X-Device",
                HeaderValue::from_str(&self.device_id.to_uppercase())?,
            );
        }
        if !route_header.is_empty() {
            headers.insert("X-Route", HeaderValue::from_str(&route_header)?);
        }
        if let Some(host) = &self.host_header {
            headers.insert(reqwest::header::HOST, HeaderValue::from_str(host)?);
        }

        let path = random_cdn_path(&self.poll_path, &mut rand::thread_rng());
        let url = format!("{}{}?t={}", base.trim_end_matches('/'), path, ts);
        self.stats.polls.fetch_add(1, Ordering::Relaxed);
        let started = Instant::now();
        let rx_before = self.stats.rx_bytes.load(Ordering::Relaxed);

        let mut attempt = 0u32;
        let resp = loop {
            let request = self
                .http
                .post(&url)
                .headers(headers.clone())
                .body(body.clone())
                .timeout(Duration::from_secs(15));
            match request.send().await {
                Ok(resp) => break resp,
                // A connect failure means the request never reached the
                // server, so replaying it cannot duplicate frames. Retrying
                // with a fresh connection fixes the intermittent SYN drops on
                // the path to the entry nodes (the old client does the same).
                Err(err)
                    if err.is_connect()
                        && !frames.is_empty()
                        && attempt < POLL_CONNECT_RETRIES =>
                {
                    attempt += 1;
                    tracing::debug!("poll connect retry {attempt} for {base}: {err}");
                    tokio::time::sleep(Duration::from_millis(150 * u64::from(attempt))).await;
                }
                Err(err) => {
                    return Err(err).with_context(|| format!("request to {base} failed"));
                }
            }
        };

        if let Some(date) = resp.headers().get(DATE).and_then(|v| v.to_str().ok()) {
            if let Ok(time) = httpdate::parse_http_date(date) {
                if let Ok(secs) = time.duration_since(UNIX_EPOCH) {
                    let offset = secs.as_secs() as i64 - now_secs();
                    let mut offsets = self.time_offsets.lock();
                    let old = offsets.get(base).copied().unwrap_or(0);
                    if (offset - old).abs() > 2 {
                        tracing::info!("time sync: {base} drift {offset}s");
                        offsets.insert(base.to_owned(), offset);
                    }
                }
            }
        }

        let status = resp.status();
        let content_type = resp
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_lowercase();
        if status == reqwest::StatusCode::FORBIDDEN {
            anyhow::bail!("HTTP 403 (check PSK/time)");
        }
        if !status.is_success() {
            anyhow::bail!("HTTP {status}");
        }
        if !content_type.contains("octet-stream") {
            anyhow::bail!("unexpected content-type {content_type:?} (mask response)");
        }

        let got_data = self.consume_response(resp).await?;
        let rx = self.stats.rx_bytes.load(Ordering::Relaxed) - rx_before;
        tracing::debug!(
            "poll {} {:?}: {} ms, up {} frame(s)/{} B, down {} B",
            base,
            route,
            started.elapsed().as_millis(),
            sent_frames,
            sent_bytes,
            rx
        );
        Ok(got_data)
    }

    fn sessions_for(&self, base: &str) -> Vec<[u8; SESSION_ID_LEN]> {
        self.by_base
            .lock()
            .get(base)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Fails only sessions pinned to the same (entry, chain) pair.
    fn fail_route_sessions(&self, base: &str, route: &[String], reason: &str) {
        let sids: Vec<_> = self.sessions_for(base);
        let targets: Vec<_> = sids
            .into_iter()
            .filter(|sid| {
                self.sessions
                    .lock()
                    .get(sid)
                    .map(|s| s.route.as_slice() == route)
                    .unwrap_or(false)
            })
            .collect();
        if targets.is_empty() {
            return;
        }
        tracing::warn!(
            "closing {} session(s) on {base} route {route:?} ({reason})",
            targets.len()
        );
        for sid in targets {
            self.close(&sid);
        }
    }

    async fn consume_response(&self, resp: reqwest::Response) -> Result<bool> {
        let mut stream = resp.bytes_stream();
        let mut buf = BytesMut::new();
        let mut stream_mode: Option<bool> = None;
        let mut got_data = false;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("response stream error")?;
            buf.extend_from_slice(&chunk);
            if stream_mode.is_none() && buf.len() >= 2 {
                let is_stream = buf[..2] == RESP_STREAM_MAGIC;
                stream_mode = Some(is_stream);
                if is_stream {
                    buf.advance(2);
                }
            }
            if stream_mode == Some(true) {
                got_data |= self.drain_records(&mut buf).await?;
            }
        }
        if stream_mode == Some(false) {
            let body = buf.freeze();
            if !body.is_empty() {
                got_data |= self.handle_batch(&body).await?;
            }
        } else if stream_mode.is_none() {
            tracing::debug!("empty poll response");
        }
        Ok(got_data)
    }

    async fn drain_records(&self, buf: &mut BytesMut) -> Result<bool> {
        let mut got = false;
        loop {
            if buf.len() < 2 {
                break;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            if len == 0 {
                buf.advance(2);
                continue;
            }
            if buf.len() < 2 + len {
                break;
            }
            buf.advance(2);
            let record = buf.split_to(len);
            match decrypt(&self.keys.enc, &record) {
                Ok(plain) => {
                    let mut offset = 0;
                    while offset < plain.len() {
                        match Frame::decode(&plain, &mut offset) {
                            Ok(frame) => got |= self.dispatch(frame).await?,
                            Err(err) => {
                                tracing::warn!("bad frame in stream: {err}");
                                break;
                            }
                        }
                    }
                }
                Err(err) => tracing::warn!("stream record decrypt failed: {err}"),
            }
        }
        Ok(got)
    }

    async fn handle_batch(&self, body: &[u8]) -> Result<bool> {
        let plain = decrypt(&self.keys.enc, body).context("batch decrypt failed")?;
        let frames = unpack_frames(&plain).context("batch unpack failed")?;
        let mut got = false;
        for frame in frames {
            got |= self.dispatch(frame).await?;
        }
        Ok(got)
    }

    async fn dispatch(&self, frame: Frame) -> Result<bool> {
        let sid = frame.session_id;
        if frame.flags & FLAG_DNS != 0 {
            tracing::debug!("DNS frame received (relay disabled)");
            return Ok(false);
        }
        let session = self.sessions.lock().get(&sid).cloned();
        let Some(session) = session else {
            return Ok(false);
        };
        let mut got = false;
        if frame.flags & FLAG_DATA != 0 && !frame.payload.is_empty() {
            self.stats
                .rx_bytes
                .fetch_add(frame.payload.len() as u64, Ordering::Relaxed);
            let len = frame.payload.len();
            if session.down_tx.send(Down::Data(frame.payload)).await.is_err() {
                tracing::debug!("session {} consumer gone", hex8(&sid));
                self.close(&sid);
                return Ok(true);
            }
            self.touch();
            got = len > 0;
        }
        if frame.flags & FLAG_FIN != 0 {
            let _ = session.down_tx.try_send(Down::Fin);
            self.close(&sid);
        }
        Ok(got)
    }

    async fn reaper(self: Arc<Self>) {
        loop {
            if !self.running.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = Instant::now();
            let expired: Vec<_> = self
                .sessions
                .lock()
                .iter()
                .filter_map(|(sid, s)| {
                    s.remove_at
                        .lock()
                        .filter(|at| *at <= now)
                        .map(|_| *sid)
                })
                .collect();
            for sid in expired {
                self.close(&sid);
            }
            if self.idle() && !self.sessions.lock().is_empty() {
                tracing::info!("idle timeout: closing {} session(s)", self.sessions.lock().len());
                let sids: Vec<_> = self.sessions.lock().keys().copied().collect();
                for sid in sids {
                    self.close(&sid);
                }
            }
        }
    }

    pub async fn stop(&self) {
        self.running.store(false, Ordering::Release);
        self.wake.notify_waiters();
        let sids: Vec<_> = self.sessions.lock().keys().copied().collect();
        for sid in sids {
            self.close(&sid);
        }
        tracing::info!("tunnel stopped");
    }

    pub fn snapshot(&self) -> Status {
        let now = Instant::now();
        let cooldowns = self.cooldowns.lock().clone();
        let failures = self.failures.lock().clone();
        let by_base = self.by_base.lock().clone();
        let last_poll = self.stats.last_poll_ms.load(Ordering::Relaxed);
        let last_error = self.stats.last_error.lock().clone();
        Status {
            profile: self.profile_name.clone(),
            running: self.running.load(Ordering::Relaxed),
            uptime_s: self.stats.started.elapsed().as_secs(),
            active_sessions: self.sessions.lock().len(),
            total_sessions: self.stats.opened.load(Ordering::Relaxed),
            polls: self.stats.polls.load(Ordering::Relaxed),
            poll_ok: self.stats.poll_ok.load(Ordering::Relaxed),
            poll_failed: self.stats.poll_failed.load(Ordering::Relaxed),
            tx_bytes: self.stats.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.stats.rx_bytes.load(Ordering::Relaxed),
            last_error: if last_error.is_empty() {
                None
            } else {
                Some(last_error)
            },
            last_poll_age_ms: if last_poll == 0 {
                None
            } else {
                Some(epoch_millis().saturating_sub(last_poll))
            },
            split_enabled: self.router.split.enabled,
            mode: self.mode(),
            urls: self
                .urls
                .iter()
                .map(|url| UrlStatus {
                    url: url.clone(),
                    failures: failures.get(url).copied().unwrap_or(0),
                    quarantined_s: cooldowns
                        .get(url)
                        .filter(|until| **until > now)
                        .map(|until| (*until - now).as_secs()),
                    sessions: by_base.get(url).map(|s| s.len()).unwrap_or(0),
                })
                .collect(),
        }
    }

    /// Called by the SOCKS layer when the local side reaches EOF.
    pub async fn local_closed(&self, sid: &[u8; SESSION_ID_LEN]) {
        self.mark_locally_closed(sid);
        self.wake.notify_waiters();
    }
}

struct Collected {
    route: Vec<String>,
    frames: Vec<Frame>,
    more: bool,
}

pub struct TunnelHandle {
    tunnel: Arc<Tunnel>,
    tasks: Vec<JoinHandle<()>>,
}

impl TunnelHandle {
    pub fn tunnel(&self) -> &Arc<Tunnel> {
        &self.tunnel
    }

    pub async fn stop(mut self) {
        self.tunnel.stop().await;
        for task in self.tasks.drain(..) {
            task.abort();
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct UrlStatus {
    pub url: String,
    pub failures: u32,
    pub quarantined_s: Option<u64>,
    pub sessions: usize,
}

#[derive(Serialize, Clone, Debug)]
pub struct Status {
    pub profile: String,
    pub running: bool,
    pub uptime_s: u64,
    pub active_sessions: usize,
    pub total_sessions: u64,
    pub polls: u64,
    pub poll_ok: u64,
    pub poll_failed: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub last_error: Option<String>,
    pub last_poll_age_ms: Option<u64>,
    pub split_enabled: bool,
    pub mode: String,
    pub urls: Vec<UrlStatus>,
}

async fn build_client(
    settings: &crate::store::Settings,
    urls: &[String],
) -> Result<(reqwest::Client, Vec<IpAddr>)> {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(20))
        .pool_max_idle_per_host(16)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_nodelay(true)
        .danger_accept_invalid_certs(!settings.verify_tls)
        .user_agent(USER_AGENT);
    if !settings.http2 {
        builder = builder.http1_only();
    }

    let mut pinned: HashMap<String, std::net::SocketAddr> = HashMap::new();
    let mut ips = Vec::new();
    for raw in urls {
        let Ok(parsed) = url::Url::parse(raw) else {
            continue;
        };
        let Some(host) = parsed.host_str() else {
            continue;
        };
        let port = parsed.port_or_known_default().unwrap_or(443);
        if let Ok(ip) = host.parse::<IpAddr>() {
            if !ips.contains(&ip) {
                ips.push(ip);
            }
            continue;
        }
        if pinned.contains_key(host) {
            continue;
        }
        let deadline = Duration::from_secs(6);
        let lookup = tokio::time::timeout(deadline, tokio::net::lookup_host((host, port))).await;
        let Ok(Ok(addrs)) = lookup else {
            tracing::warn!("cannot pin entry server {host}:{port}");
            continue;
        };
        // Prefer IPv4 for TUN exclusion routes; IPv6 is still usable in
        // proxy mode, but Windows route management here is IPv4-only.
        let chosen = addrs.into_iter().find(|addr| addr.is_ipv4());
        if let Some(addr) = chosen {
            pinned.insert(host.to_owned(), addr);
            if !ips.contains(&addr.ip()) {
                ips.push(addr.ip());
            }
        }
    }
    for (host, addr) in pinned {
        builder = builder.resolve(&host, addr);
    }
    let client = builder.build().context("cannot build HTTP client")?;
    Ok((client, ips))
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn hex8(sid: &[u8; SESSION_ID_LEN]) -> String {
    sid[..4].iter().map(|b| format!("{b:02x}")).collect()
}

/// Best-effort human-readable target for logs (`ip:port` stays unchanged).
pub fn host_is_ip(host: &str) -> bool {
    host.parse::<IpAddr>().is_ok()
}
