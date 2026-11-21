//! Tiny local control plane: one JSON request per line, one JSON reply.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::tunnel::Tunnel;

#[derive(Serialize, Deserialize)]
pub struct StateFile {
    pub pid: u32,
    pub socks: String,
    #[serde(default)]
    pub http: String,
    pub control: String,
    pub profile: String,
    pub started_at: i64,
}

pub fn state_path(dir: &Path) -> PathBuf {
    dir.join("state.json")
}

pub fn write_state(dir: &Path, state: &StateFile) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    std::fs::write(state_path(dir), serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

pub fn read_state(dir: &Path) -> Option<StateFile> {
    let text = std::fs::read_to_string(state_path(dir)).ok()?;
    serde_json::from_str(&text).ok()
}

pub fn clear_state(dir: &Path) {
    let _ = std::fs::remove_file(state_path(dir));
}

#[derive(Clone)]
pub struct ControlCtx {
    pub tunnel: Arc<Tunnel>,
    pub socks: String,
    pub http: String,
    pub shutdown: Arc<Notify>,
    pub stopping: Arc<AtomicBool>,
}

pub async fn serve(bind: String, ctx: ControlCtx, running: Arc<AtomicBool>) -> Result<()> {
    let listener = TcpListener::bind(&bind)
        .await
        .with_context(|| format!("cannot bind control listener on {bind}"))?;
    serve_on(listener, &bind, ctx, running).await
}

pub async fn serve_on(
    listener: TcpListener,
    bind: &str,
    ctx: ControlCtx,
    running: Arc<AtomicBool>,
) -> Result<()> {
    tracing::info!("control API on {bind}");
    while running.load(Ordering::Acquire) {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(err) => {
                tracing::warn!("control accept: {err}");
                continue;
            }
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _ = handle(stream, ctx).await;
        });
    }
    Ok(())
}

async fn handle(stream: TcpStream, ctx: ControlCtx) -> Result<()> {
    stream.set_nodelay(true).ok();
    let (rd, mut wr) = stream.into_split();
    let mut reader = BufReader::new(rd);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await?;
    if n == 0 {
        return Ok(());
    }
    let request: Value = serde_json::from_str(line.trim()).unwrap_or_else(|_| json!({"cmd": "status"}));
    let cmd = request.get("cmd").and_then(|v| v.as_str()).unwrap_or("status");
    let response = match cmd {
        "status" => json!({
            "ok": true,
            "pid": std::process::id(),
            "socks": ctx.socks,
            "http": ctx.http,
            "status": ctx.tunnel.snapshot(),
        }),
        "stop" => {
            ctx.stopping.store(true, Ordering::Release);
            ctx.shutdown.notify_waiters();
            json!({"ok": true, "stopping": true})
        }
        "ping" => json!({"ok": true, "pong": true}),
        other => json!({"ok": false, "error": format!("unknown command {other}")}),
    };
    let mut out = serde_json::to_vec(&response)?;
    out.push(b'\n');
    wr.write_all(&out).await?;
    wr.flush().await?;
    Ok(())
}

/// Sends a control command to a running daemon.
pub async fn request(addr: &str, cmd: Value) -> Result<Value> {
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        TcpStream::connect(addr),
    )
    .await
    .context("control request timed out")??;
    let (rd, mut wr) = stream.into_split();
    let mut line = serde_json::to_vec(&cmd)?;
    line.push(b'\n');
    wr.write_all(&line).await?;
    wr.flush().await?;
    let mut reader = BufReader::new(rd);
    let mut reply = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.read_line(&mut reply),
    )
    .await
    .context("control reply timed out")??;
    Ok(serde_json::from_str(reply.trim())?)
}
