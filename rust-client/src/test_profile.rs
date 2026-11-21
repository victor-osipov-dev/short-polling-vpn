//! Profile connection tester: starts a temporary tunnel + SOCKS listener and
//! fetches the check URL through it, so the whole path is exercised.

use anyhow::{Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
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
            // A single-hop route has no chain; show the node id instead of
            // the raw entry URL.
            let single = match &decision {
                Decision::Tunnel { entry, chain, .. } if chain.is_empty() => {
                    tunnel.router.node_name(entry)
                }
                _ => None,
            };
            result.route = single.unwrap_or_else(|| describe(decision));
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
                    } else if let Some(ip) = parse_exit_ip(&body) {
                        result.exit_ip = ip;
                        result.ok = true;
                    } else {
                        result.error = "cannot parse exit IP from response".into();
                    }
                }
                Err(err) => result.error = format!("read body: {err}"),
            }
        }
        Err(err) => result.error = describe_reqwest_error(&err),
    }

    socks_task.abort();
    handle.stop().await;
    result
}

/// Extracts the exit IP from several common check endpoints, matching the
/// Android client: Cloudflare's `ip=` trace, a bare IP (ipify/ifconfig.me)
/// and JSON bodies with `ip`, `query` or `origin` keys.
fn parse_exit_ip(body: &str) -> Option<String> {
    if let Some(ip) = body.lines().find_map(|line| line.strip_prefix("ip=")) {
        let ip = ip.trim();
        if !ip.is_empty() {
            return Some(ip.to_owned());
        }
    }
    let trimmed = body.trim();
    if trimmed.parse::<std::net::IpAddr>().is_ok() {
        return Some(trimmed.to_owned());
    }
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        for key in ["ip", "query", "origin", "addr"] {
            if let Some(ip) = value.get(key).and_then(|v| v.as_str()) {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return Some(ip.to_owned());
                }
            }
        }
    }
    None
}

/// `reqwest::Error` only prints the outer wrapper, which hides the useful
/// part ("tcp connect error: deadline has elapsed"). Walk the source chain.
fn describe_reqwest_error(err: &reqwest::Error) -> String {
    use std::error::Error as _;
    let mut text = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        let next = cause.to_string();
        if !next.is_empty() && !text.contains(&next) {
            text.push_str(": ");
            text.push_str(&next);
        }
        source = cause.source();
    }
    text
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
/// compete for CPU and distort latency). Each result is reported as soon as it
/// is ready, and a finished slot immediately picks up the next profile.
pub async fn test_many_stream<F>(
    profiles: Vec<ResolvedProfile>,
    cache_dir: std::path::PathBuf,
    target: String,
    timeout: Duration,
    parallel: usize,
    mut on_result: F,
) -> Vec<TestResult>
where
    F: FnMut(TestResult),
{
    let mut profiles = profiles.into_iter();
    let mut tasks = FuturesUnordered::new();
    let spawn = |profile: ResolvedProfile, cache: std::path::PathBuf, target: String| {
        tokio::spawn(async move { test_profile(profile, &cache, &target, timeout).await })
    };
    for _ in 0..parallel.max(1) {
        if let Some(profile) = profiles.next() {
            tasks.push(spawn(profile, cache_dir.clone(), target.clone()));
        }
    }
    let mut results = Vec::new();
    while let Some(joined) = tasks.next().await {
        if let Ok(result) = joined {
            on_result(result.clone());
            results.push(result);
        }
        if let Some(profile) = profiles.next() {
            tasks.push(spawn(profile, cache_dir.clone(), target.clone()));
        }
    }
    results
}

/// Collects all results before returning (used by callers that need the whole
/// list, e.g. JSON output).
pub async fn test_many(
    profiles: Vec<ResolvedProfile>,
    cache_dir: std::path::PathBuf,
    target: String,
    timeout: Duration,
    parallel: usize,
) -> Vec<TestResult> {
    test_many_stream(profiles, cache_dir, target, timeout, parallel, |_| {}).await
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
    parse_exit_ip(&body).context("cannot parse exit IP from response")
}

#[allow(dead_code)]
fn _assert_send_sync() {
    fn is_send<T: Send>() {}
    is_send::<Arc<Tunnel>>();
}

#[cfg(test)]
mod tests {
    use super::parse_exit_ip;

    #[test]
    fn parses_cloudflare_trace() {
        let body = "fl=123abc\nh=www.cloudflare.com\nip=2a0c:5d00:3001::a971:a124\nloc=RU\n";
        assert_eq!(
            parse_exit_ip(body).as_deref(),
            Some("2a0c:5d00:3001::a971:a124")
        );
    }

    #[test]
    fn parses_bare_ip() {
        assert_eq!(parse_exit_ip(" 45.94.118.166\n").as_deref(), Some("45.94.118.166"));
    }

    #[test]
    fn parses_json_apis() {
        assert_eq!(parse_exit_ip(r#"{"ip":"1.2.3.4"}"#).as_deref(), Some("1.2.3.4"));
        assert_eq!(
            parse_exit_ip(r#"{"query":"5.6.7.8","city":"X"}"#).as_deref(),
            Some("5.6.7.8")
        );
        assert_eq!(
            parse_exit_ip(r#"{"origin":"9.8.7.6"}"#).as_deref(),
            Some("9.8.7.6")
        );
    }

    #[test]
    fn rejects_unrelated_text() {
        assert_eq!(parse_exit_ip("<html>hello</html>"), None);
        assert_eq!(parse_exit_ip(""), None);
    }
}
