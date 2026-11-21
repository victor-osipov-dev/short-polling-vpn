//! Minimal HTTP/1.1 proxy backed by tunnel sessions.
//!
//! Windows applications (and the old desktop client) expect a normal HTTP
//! proxy in `ProxyServer`, not a `socks=` entry that most of them ignore. We
//! accept CONNECT for HTTPS and absolute-form requests for plain HTTP and
//! forward both through the same router as the SOCKS5 listener.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::routing::Decision;
use crate::socks::relay;
use crate::tunnel::Tunnel;

/// Serves an already-bound HTTP proxy listener.
pub async fn serve_listener(listener: TcpListener, tunnel: Arc<Tunnel>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let tunnel = tunnel.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(tunnel, stream, peer).await {
                        tracing::debug!("http proxy {peer}: {err:#}");
                    }
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn handle(tunnel: Arc<Tunnel>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    stream.set_nodelay(true).ok();
    let header = read_header(&mut stream).await?;
    let first_line = header
        .split("\r\n")
        .next()
        .unwrap_or("")
        .trim()
        .to_owned();
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_uppercase();
    let target = parts.next().unwrap_or("").to_owned();

    if method == "CONNECT" {
        if let Some((host, port)) = parse_authority(&target) {
            return proxy_bytes(&tunnel, stream, peer, host, port, None).await;
        }
        return bad_request(&mut stream, "bad CONNECT target").await;
    }

    if let Ok(url) = url::Url::parse(&target) {
        let scheme = url.scheme();
        if scheme == "http" || scheme == "https" {
            let host = url.host_str().context("proxy target has no host")?.to_owned();
            let port = url.port_or_known_default().unwrap_or(80);
            let mut path = url.path().to_owned();
            if let Some(query) = url.query() {
                path.push('?');
                path.push_str(query);
            }
            let rest = header
                .split_once("\r\n")
                .map(|(_, rest)| rest)
                .unwrap_or("");
            let rewritten = format!("{method} {path} HTTP/1.1\r\n{rest}\r\n");
            return proxy_bytes(&tunnel, stream, peer, host, port, Some(rewritten)).await;
        }
    }

    bad_request(&mut stream, "only CONNECT and absolute HTTP URLs are supported").await
}

async fn proxy_bytes(
    tunnel: &Arc<Tunnel>,
    mut stream: TcpStream,
    peer: SocketAddr,
    host: String,
    port: u16,
    initial: Option<String>,
) -> Result<()> {
    let decision = tunnel.route(&host);
    match decision {
        Decision::Direct => {
            let target = format!("{host}:{port}");
            let upstream = match tokio::time::timeout(
                Duration::from_secs(10),
                TcpStream::connect(&target),
            )
            .await
            {
                Ok(Ok(socket)) => socket,
                Ok(Err(err)) => {
                    let _ = stream.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n").await;
                    tracing::debug!("http proxy {peer}: direct connect {target}: {err}");
                    return Ok(());
                }
                Err(_) => {
                    let _ = stream.write_all(b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n").await;
                    return Ok(());
                }
            };
            upstream.set_nodelay(true).ok();
            if initial.is_none() {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            let (mut client_rd, mut client_wr) = stream.into_split();
            let (mut up_rd, mut up_wr) = upstream.into_split();
            if let Some(data) = initial {
                up_wr.write_all(data.as_bytes()).await?;
            }
            let c2u = async {
                let _ = tokio::io::copy(&mut client_rd, &mut up_wr).await;
                let _ = up_wr.shutdown().await;
            };
            let u2c = async {
                let _ = tokio::io::copy(&mut up_rd, &mut client_wr).await;
                let _ = client_wr.shutdown().await;
            };
            tokio::join!(c2u, u2c);
            Ok(())
        }
        Decision::Error(reason) => {
            tracing::warn!("http proxy {peer}: {reason} for {host}:{port}");
            gateway_error(&mut stream, 502, "Bad Gateway", &reason).await
        }
        decision => {
            let (session, down_rx) = tunnel
                .open(host.clone(), port, decision)
                .await
                .with_context(|| format!("cannot open tunnel session for {host}:{port}"))?;
            let mut stream = stream;
            if let Some(data) = initial {
                session.push_outgoing(Bytes::from(data)).await;
            } else {
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
            }
            tracing::debug!("http proxy {peer} -> {host}:{port}");
            relay(stream, session, down_rx, tunnel.clone()).await;
            Ok(())
        }
    }
}

/// Reads the request header without consuming anything after `\r\n\r\n`.
async fn read_header(stream: &mut TcpStream) -> Result<String> {
    let mut buf = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    while buf.len() < 16 * 1024 {
        stream.read_exact(&mut byte).await?;
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8(buf).context("non-UTF8 HTTP header");
        }
    }
    anyhow::bail!("HTTP header is too large")
}

fn parse_authority(target: &str) -> Option<(String, u16)> {
    let (host, port) = target.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']').to_owned();
    if host.is_empty() {
        return None;
    }
    Some((host, port.parse().ok()?))
}

async fn bad_request(stream: &mut TcpStream, reason: &str) -> Result<()> {
    gateway_error(stream, 400, "Bad Request", reason).await
}

async fn gateway_error(stream: &mut TcpStream, code: u16, label: &str, reason: &str) -> Result<()> {
    let body = format!("{reason}\r\n");
    let head = format!(
        "HTTP/1.1 {code} {label}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body.as_bytes()).await?;
    Ok(())
}
