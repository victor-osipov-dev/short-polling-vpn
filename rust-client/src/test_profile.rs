//! Profile connection tester: starts a temporary tunnel + SOCKS listener and
//! fetches the check URL through it, so the whole path is exercised.

use anyhow::{Context, Result};
use serde::Serialize;
use std::net::TcpListener as StdListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::routing::Decision;
use crate::store::ResolvedProfile;
use crate::tunnel::Tunnel;

#[derive(Serialize, Clone, Debug)]
pub struct TestResult {
    pub profile: String,
    pub ok: bool,
    pub latency_ms: u64,
    pub exit_ip: String,
    pub route: String,
    pub category: String,
    pub error: String,
}

pub async fn test_profile(
    profile: ResolvedProfile,
    cache_dir: &std::path::Path,
    target: &str,
    timeout: Duration,
) -> TestResult {
    let name = profile.name.clone();
    let mut result = TestResult {
        profile: name,
        ok: false,
        latency_ms: 0,
        exit_ip: String::new(),
        route: String::new(),
        category: String::new(),
        error: String::new(),
    };

    let tunnel = match Tunnel::new(profile, cache_dir).await {
        Ok(t) => t,
        Err(err) => {
            result.error = format!("{err:#}");
            return result;
        }
    };
    let handle = tunnel.start();

    // Reserve a port, then hand the listener to the SOCKS server.
    let listener = match StdListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(err) => {
            result.error = format!("cannot bind tester listener: {err}");
            handle.stop().await;
            return result;
        }
    };
    let port = match listener.local_addr() {
        Ok(addr) => addr.port(),
        Err(err) => {
            result.error = format!("{err}");
            handle.stop().await;
            return result;
        }
    };
    listener.set_nonblocking(true).ok();
    let listener = tokio::net::TcpListener::from_std(listener).expect("valid listener");
    let socks_task = tokio::spawn(crate::socks::serve_listener(listener, tunnel.clone()));

    if let Ok(url) = url::Url::parse(target) {
        if let Some(host) = url.host_str() {
            let decision = tunnel.route(host);
            result.category = decision.category().as_str().to_owned();
            result.route = describe(decision);
        }
    }

    let proxy = match reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}")) {
        Ok(p) => p,
        Err(err) => {
            result.error = format!("{err}");
            socks_task.abort();
            handle.stop().await;
            return result;
        }
    };
    let client = match reqwest::Client::builder()
        .proxy(proxy)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent("spvpn-tester/0.1")
        .build()
    {
        Ok(c) => c,
        Err(err) => {
            result.error = format!("{err}");
            socks_task.abort();
            handle.stop().await;
            return result;
        }
    };

    let started = Instant::now();
    match client.get(target).send().await {
        Ok(resp) => {
            let status = resp.status();
            match resp.text().await {
                Ok(body) => {
                    result.latency_ms = started.elapsed().as_millis() as u64;
                    if !status.is_success() {
                        result.error = format!("HTTP {status}");
                    } else {
                        result.exit_ip = body
                            .lines()
                            .find_map(|line| line.strip_prefix("ip="))
                            .unwrap_or("")
                            .trim()
                            .to_owned();
                        result.ok = true;
                        if result.exit_ip.is_empty() {
                            result.error = "no ip= line in response".into();
                        }
                    }
                }
                Err(err) => result.error = format!("read body: {err}"),
            }
        }
        Err(err) => result.error = format!("{err:#}"),
    }

    socks_task.abort();
    handle.stop().await;
    result
}

pub fn describe(decision: Decision) -> String {
    match decision {
        Decision::Direct => "direct".into(),
        Decision::Error(reason) => format!("error: {reason}"),
        Decision::Tunnel { entry, chain, .. } => {
            if chain.is_empty() {
                entry
            } else {
                chain.join(" -> ")
            }
        }
    }
}

impl Decision {
    pub fn category(&self) -> crate::routing::Category {
        match self {
            Decision::Tunnel { category, .. } => *category,
            _ => crate::routing::Category::NonRu,
        }
    }
}

/// Runs tests with limited concurrency (starting many tunnels at once would
/// compete for CPU and distort latency).
pub async fn test_many(
    profiles: Vec<ResolvedProfile>,
    cache_dir: std::path::PathBuf,
    target: String,
    timeout: Duration,
    parallel: usize,
) -> Vec<TestResult> {
    let mut results = Vec::new();
    for chunk in profiles.chunks(parallel.max(1)) {
        let mut tasks = Vec::new();
        for profile in chunk {
            let profile = profile.clone();
            let cache = cache_dir.clone();
            let target = target.clone();
            tasks.push(tokio::spawn(async move {
                test_profile(profile, &cache, &target, timeout).await
            }));
        }
        for task in tasks {
            if let Ok(result) = task.await {
                results.push(result);
            }
        }
    }
    results
}

/// Convenience for a single quick exit-IP lookup without a profile.
pub async fn public_ip() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let body = client
        .get("https://www.cloudflare.com/cdn-cgi/trace")
        .send()
        .await?
        .text()
        .await
        .context("cannot read trace response")?;
    Ok(body
        .lines()
        .find_map(|line| line.strip_prefix("ip="))
        .unwrap_or("")
        .to_owned())
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send<T: Send>() {}
    is_send::<Arc<Tunnel>>();
}
