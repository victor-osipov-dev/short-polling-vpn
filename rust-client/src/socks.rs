//! SOCKS5 server (CONNECT only) that maps every TCP stream to a tunnel
//! session. Direct-routed destinations are connected locally.

use anyhow::{Context, Result};
use bytes::Bytes;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::routing::Decision;
use crate::tunnel::{Down, Session, Tunnel};

const SOCKS_VERSION: u8 = 5;
const CMD_CONNECT: u8 = 1;

pub async fn serve(tunnel: Arc<Tunnel>, bind: String, running: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("cannot bind SOCKS5 listener on {bind}"))?;
    let addr = listener.local_addr()?;
    tracing::info!("SOCKS5 listening on {addr}");
    while running.load(Ordering::Acquire) {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let tunnel = tunnel.clone();
                tokio::spawn(async move {
                    if let Err(err) = handle(tunnel, stream, peer).await {
                        tracing::debug!("socks {peer}: {err:#}");
                    }
                });
            }
            Err(err) => {
                tracing::warn!("accept failed: {err}");
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
    }
    Ok(())
}

/// Serves an already-bound listener (used by the connection tester).
pub async fn serve_listener(listener: TcpListener, tunnel: Arc<Tunnel>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let tunnel = tunnel.clone();
                tokio::spawn(async move {
                    let _ = handle(tunnel, stream, peer).await;
                });
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn handle(tunnel: Arc<Tunnel>, mut stream: TcpStream, peer: SocketAddr) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (host, port) = handshake(&mut stream).await?;
    tracing::debug!("socks {peer} CONNECT {host}:{port}");

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
                Ok(Ok(s)) => s,
                Ok(Err(err)) => {
                    tracing::debug!("direct connect {target}: {err}");
                    reply(&mut stream, 0x05).await?;
                    return Ok(());
                }
                Err(_) => {
                    reply(&mut stream, 0x06).await?;
                    return Ok(());
                }
            };
            upstream.set_nodelay(true).ok();
            reply(&mut stream, 0x00).await?;
            let (mut client_rd, mut client_wr) = stream.into_split();
            let (mut up_rd, mut up_wr) = upstream.into_split();
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
            tracing::warn!("socks {peer}: {reason} for {host}:{port}");
            reply(&mut stream, 0x04).await?;
            Ok(())
        }
        Decision::Tunnel {
            entry,
            chain,
            category,
        } => {
            let route_desc = if chain.is_empty() {
                entry.clone()
            } else {
                format!("{} ({})", entry, chain.join(" -> "))
            };
            let (session, down_rx) = tunnel
                .open(host.clone(), port, Decision::Tunnel {
                    entry,
                    chain,
                    category,
                })
                .await
                .with_context(|| format!("cannot open tunnel session for {host}:{port}"))?;
            reply(&mut stream, 0x00).await?;
            tracing::debug!(
                "socks {peer} -> {host}:{port} via {route_desc} [{}]",
                category.as_str()
            );
            relay(stream, session, down_rx, tunnel.clone()).await;
            Ok(())
        }
    }
}

/// Bidirectional bridge between the local socket and a tunnel session.
async fn relay(
    stream: TcpStream,
    session: Arc<Session>,
    mut down_rx: mpsc::Receiver<Down>,
    tunnel: Arc<Tunnel>,
) {
    let sid = session.id;
    let (mut reader, mut writer) = stream.into_split();

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
            // Local side closed: flush remaining outbound data, then wait a
            // little for the remote FIN.
            if tokio::time::timeout(Duration::from_secs(30), &mut writer_task)
                .await
                .is_err()
            {
                writer_task.abort();
            }
        }
        _ = &mut writer_task => {
            reader_task.abort();
        }
    }
    tunnel.close(&sid);
}

async fn handshake(stream: &mut TcpStream) -> Result<(String, u16)> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS_VERSION {
        anyhow::bail!("unsupported SOCKS version {}", head[0]);
    }
    let mut methods = vec![0u8; head[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&0x00) {
        stream.write_all(&[SOCKS_VERSION, 0xFF]).await?;
        anyhow::bail!("no acceptable auth method");
    }
    stream.write_all(&[SOCKS_VERSION, 0x00]).await?;

    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != SOCKS_VERSION {
        anyhow::bail!("bad request version");
    }
    if req[1] != CMD_CONNECT {
        reply(stream, 0x07).await?;
        anyhow::bail!("unsupported SOCKS command {}", req[1]);
    }
    let host = match req[3] {
        0x01 => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;
            IpAddr::from(buf).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut buf = vec![0u8; len[0] as usize];
            stream.read_exact(&mut buf).await?;
            String::from_utf8(buf).context("non-UTF8 SOCKS host")?
        }
        0x04 => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;
            IpAddr::from(buf).to_string()
        }
        atyp => {
            reply(stream, 0x08).await?;
            anyhow::bail!("unsupported address type {atyp}");
        }
    };
    let mut port = [0u8; 2];
    stream.read_exact(&mut port).await?;
    Ok((host, u16::from_be_bytes(port)))
}

async fn reply(stream: &mut TcpStream, code: u8) -> Result<()> {
    stream
        .write_all(&[SOCKS_VERSION, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}
