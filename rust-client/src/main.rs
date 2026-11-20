#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
#[cfg(feature = "tui")]
use std::io::IsTerminal;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Notify;

use spvpn::control::{self, ControlCtx, StateFile};
use spvpn::routing::Decision;
use spvpn::store::{Store, MANUAL_PROFILE_ID};
use spvpn::tunnel::Tunnel;

#[derive(Parser)]
#[command(
    name = "spvpn",
    version,
    about = "Short Polling VPN — fast, minimal Rust client",
    disable_help_subcommand = true
)]
struct Cli {
    /// Config directory (default: %APPDATA%/spvpn on Windows, ~/.config/spvpn elsewhere)
    #[arg(long, global = true, env = "SPVPN_DIR")]
    dir: Option<PathBuf>,
    /// Verbose protocol-level logging
    #[arg(short, long, global = true)]
    verbose: bool,
    /// Machine-readable JSON output
    #[arg(long, global = true)]
    json: bool,
    /// Do not open the desktop window (use CLI/TUI instead)
    #[arg(long, global = true)]
    no_gui: bool,
    /// Start the desktop app hidden in the system tray
    #[arg(long, global = true)]
    minimized: bool,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Connect and serve a local SOCKS5 proxy
    Run(RunArgs),
    /// List profiles
    Profiles,
    /// Select the active profile
    Use { profile: String },
    /// Manage subscriptions
    Subs(SubsArgs),
    /// Test profile connectivity (exit IP, latency, route)
    Test(TestArgs),
    /// Show daemon status
    Status,
    /// Stop the running daemon
    Stop,
    /// Show or change settings
    Config(ConfigArgs),
    /// Show the client log
    Logs(LogsArgs),
}

#[derive(Args)]
struct RunArgs {
    /// Profile name or id (default: active profile)
    #[arg(short, long)]
    profile: Option<String>,
    /// SOCKS5 listen address override
    #[arg(long)]
    socks: Option<String>,
    /// Control API listen address override
    #[arg(long)]
    control: Option<String>,
    /// Do not start the interactive dashboard
    #[arg(long)]
    no_tui: bool,
}

#[derive(Args)]
struct SubsArgs {
    #[command(subcommand)]
    cmd: SubsCmd,
}

#[derive(Subcommand)]
enum SubsCmd {
    /// Add a subscription from URL, file path or inline JSON
    Add {
        source: String,
        #[arg(short, long)]
        name: Option<String>,
    },
    /// List subscriptions
    List,
    /// Remove a subscription and its profiles
    Remove { id: String },
    /// Refresh one or all subscriptions
    Refresh { id: Option<String> },
}

#[derive(Args)]
struct TestArgs {
    /// Profile name or id; omit to test the active one
    profile: Option<String>,
    /// Test every profile
    #[arg(long)]
    all: bool,
    /// Number of profiles tested simultaneously
    #[arg(long, default_value_t = 2)]
    parallel: usize,
    /// Per-test timeout, seconds
    #[arg(long, default_value_t = 20)]
    timeout: u64,
    /// URL used to verify connectivity
    #[arg(long)]
    target: Option<String>,
}

#[derive(Args)]
struct ConfigArgs {
    #[command(subcommand)]
    cmd: ConfigCmd,
}

#[derive(Subcommand)]
enum ConfigCmd {
    /// Print the whole configuration (secrets included)
    Show,
    /// Print the config file path
    Path,
    /// Change one setting
    Set { key: String, value: String },
}

#[derive(Args)]
struct LogsArgs {
    /// Follow the log
    #[arg(short, long)]
    follow: bool,
    /// Number of kilobytes to show
    #[arg(long, default_value_t = 64)]
    kb: usize,
}

fn config_dir(cli: &Cli) -> PathBuf {
    cli.dir
        .clone()
        .or_else(|| std::env::var_os("SPVPN_DIR").map(PathBuf::from))
        .unwrap_or_else(|| {
            dirs::config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("spvpn")
        })
}

/// Release builds use the Windows GUI subsystem so double-clicking the exe
/// never flashes a console window. Attach to the parent terminal for CLI
/// output, or allocate a console when a CLI command was started standalone.
#[cfg(all(windows, not(debug_assertions)))]
fn setup_console() {
    const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
    #[link(name = "kernel32")]
    extern "system" {
        fn AttachConsole(process_id: u32) -> i32;
        fn AllocConsole() -> i32;
    }

    let args: Vec<String> = std::env::args().collect();
    let cli = args.iter().any(|arg| {
        matches!(
            arg.as_str(),
            "run"
                | "profiles"
                | "use"
                | "subs"
                | "test"
                | "status"
                | "stop"
                | "config"
                | "logs"
                | "--no-gui"
                | "--help"
                | "-h"
                | "--version"
                | "-V"
        )
    });
    if !cli {
        return;
    }
    let attached = unsafe { AttachConsole(ATTACH_PARENT_PROCESS) } != 0;
    if !attached {
        unsafe {
            AllocConsole();
        }
    }
}

#[cfg(not(all(windows, not(debug_assertions))))]
fn setup_console() {}

#[tokio::main]
async fn main() {
    setup_console();
    let cli = Cli::parse();
    let dir = config_dir(&cli);
    let result = run(cli, dir.clone()).await;
    if let Err(err) = result {
        tracing::error!("{err:#}");
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli, dir: PathBuf) -> Result<()> {
    std::fs::create_dir_all(&dir)?;
    #[cfg(all(feature = "gui", windows))]
    let gui_mode = !cli.no_gui && cli.cmd.is_none();
    #[cfg(not(all(feature = "gui", windows)))]
    let gui_mode = false;
    #[cfg(feature = "tui")]
    let tui_mode = {
        let interactive = std::io::stdout().is_terminal() && std::io::stdin().is_terminal();
        match &cli.cmd {
            None => interactive && !gui_mode,
            Some(Cmd::Run(args)) => interactive && !args.no_tui,
            _ => false,
        }
    };
    #[cfg(not(feature = "tui"))]
    let tui_mode = false;
    spvpn::logging::init(&dir, cli.verbose, !tui_mode && !gui_mode);

    #[cfg(all(feature = "gui", windows))]
    if gui_mode {
        return spvpn::gui::run(dir, cli.minimized);
    }

    match cli.cmd {
        None => {
            #[cfg(feature = "tui")]
            if tui_mode {
                return spvpn::tui::run(dir, None).await;
            }
            cmd_run(
                &dir,
                RunArgs {
                    profile: None,
                    socks: None,
                    control: None,
                    no_tui: true,
                },
                cli.json,
            )
            .await
        }
        Some(Cmd::Run(args)) => {
            let selected = args.profile.clone();
            #[cfg(feature = "tui")]
            if tui_mode {
                return spvpn::tui::run(dir, selected).await;
            }
            let _ = selected;
            cmd_run(&dir, args, cli.json).await
        }
        Some(Cmd::Profiles) => cmd_profiles(&dir, cli.json),
        Some(Cmd::Use { profile }) => cmd_use(&dir, &profile, cli.json),
        Some(Cmd::Subs(args)) => cmd_subs(&dir, args, cli.json).await,
        Some(Cmd::Test(args)) => cmd_test(&dir, args, cli.json).await,
        Some(Cmd::Status) => cmd_status(&dir, cli.json).await,
        Some(Cmd::Stop) => cmd_stop(&dir).await,
        Some(Cmd::Config(args)) => cmd_config(&dir, args, cli.json),
        Some(Cmd::Logs(args)) => cmd_logs(&dir, args).await,
    }
}

/// Binds a listener, moving to the next free port when the preferred one is
/// already taken (the desktop app keeps 8890/8891 while it is running).
async fn bind_listener(addr: &str, label: &str) -> Result<TcpListener> {
    let parsed: std::net::SocketAddr = addr
        .parse()
        .with_context(|| format!("invalid {label} address {addr:?} (expected IP:port)"))?;
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
            anyhow::bail!(
                "{label} port {} is busy (is another VPN client running?)",
                parsed.port()
            )
        }
        Err(err) => {
            Err(err).with_context(|| format!("cannot bind {label} listener on {addr}"))
        }
    }
}

async fn cmd_run(dir: &std::path::Path, args: RunArgs, json: bool) -> Result<()> {
    let store = Store::load(dir)?;
    let profile = match args.profile.as_deref() {
        Some(needle) if needle != MANUAL_PROFILE_ID => Some(
            store
                .find_profile(needle)
                .with_context(|| format!("profile {needle:?} not found"))?
                .clone(),
        ),
        Some(_) => None,
        None => store.active_profile().cloned(),
    };
    let mut resolved = store.resolve(profile.as_ref())?;
    let mode = resolved.mode.clone();
    let vpn_mode = mode.eq_ignore_ascii_case("vpn");
    let socks = args
        .socks
        .clone()
        .unwrap_or_else(|| resolved.settings.socks_listen.clone());
    let control_addr = args
        .control
        .clone()
        .unwrap_or_else(|| resolved.settings.control_listen.clone());
    resolved.settings.socks_listen = socks.clone();

    // Entry servers are resolved inside `Tunnel::new`, before the TUN routes
    // exist, so the pinned addresses are usable for the /32 exclusions.
    #[cfg(all(feature = "gui", windows))]
    let tun_config = if vpn_mode {
        if !spvpn::tun::is_elevated() {
            anyhow::bail!(
                "VPN mode requires Administrator rights; start the terminal as Administrator"
            );
        }
        Some(spvpn::tun::TunConfig::from_settings(&resolved.settings)?)
    } else {
        None
    };
    #[cfg(not(all(feature = "gui", windows)))]
    if vpn_mode {
        anyhow::bail!(
            "VPN mode is not available in this build; use the GUI build or switch the profile to Proxy mode"
        );
    }

    let tunnel = Tunnel::new(resolved, &dir.join("cache")).await?;
    let running = Arc::new(AtomicBool::new(true));
    let socks_listener = bind_listener(&socks, "SOCKS5").await?;
    let actual_socks = socks_listener.local_addr()?.to_string();
    if actual_socks != socks {
        tracing::warn!("{socks} is busy, using {actual_socks} for SOCKS5");
    }

    let shutdown = Arc::new(Notify::new());
    let stopping = Arc::new(AtomicBool::new(false));
    let control_listener = bind_listener(&control_addr, "control").await?;
    let actual_control = control_listener.local_addr()?.to_string();
    if actual_control != control_addr {
        tracing::warn!("{control_addr} is busy, using {actual_control} for control API");
    }
    let handle = tunnel.start();

    let socks_task = tokio::spawn(spvpn::socks::serve_listener(socks_listener, tunnel.clone()));
    let control_task = {
        let ctx = ControlCtx {
            tunnel: tunnel.clone(),
            socks: actual_socks.clone(),
            shutdown: shutdown.clone(),
            stopping: stopping.clone(),
        };
        let control_running = running.clone();
        let label = actual_control.clone();
        tokio::spawn(async move {
            if let Err(err) = control::serve_on(control_listener, &label, ctx, control_running).await {
                tracing::error!("control API: {err:#}");
            }
        })
    };

    #[cfg(all(feature = "gui", windows))]
    let mut tun = None;
    #[cfg(all(feature = "gui", windows))]
    if let Some(config) = tun_config {
        let cache = Arc::new(spvpn::tun::DomainCache::default());
        let runtime = spvpn::tun::TunRuntime::start(tunnel.clone(), config, cache, dir)
            .await
            .context("cannot start VPN mode (run as Administrator)")?;
        tracing::info!("mode: VPN via TUN {}", runtime.interface);
        tun = Some(runtime);
    }

    let state = StateFile {
        pid: std::process::id(),
        socks: actual_socks.clone(),
        control: actual_control.clone(),
        profile: tunnel.profile_name.clone(),
        started_at: spvpn::subscription::now_secs(),
    };
    control::write_state(dir, &state)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&state)?);
    } else {
        println!("Short Polling VPN {} — connected", spvpn::VERSION);
        println!("  profile : {}", tunnel.profile_name);
        println!(
            "  mode    : {}",
            if vpn_mode { "VPN (TUN)" } else { "Proxy (SOCKS5)" }
        );
        println!("  SOCKS5  : {actual_socks}");
        println!("  control : {actual_control}");
        println!("  press Ctrl+C to stop");
    }

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = shutdown.notified() => {},
    }

    tracing::info!("shutting down");
    running.store(false, Ordering::Release);
    socks_task.abort();
    control_task.abort();
    #[cfg(all(feature = "gui", windows))]
    if let Some(tun) = tun.take() {
        tun.stop().await;
    }
    handle.stop().await;
    control::clear_state(dir);
    Ok(())
}

fn cmd_profiles(dir: &std::path::Path, json: bool) -> Result<()> {
    let store = Store::load(dir)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&store.profiles)?);
        return Ok(());
    }
    if store.profiles.is_empty() && !store.has_manual() {
        println!("No profiles. Add a subscription: spvpn subs add <url>");
        return Ok(());
    }
    let active = store.active.as_deref().unwrap_or("");
    for sub in &store.subscriptions {
        println!("{}  ({})", sub.name, sub.source);
        for profile in store.profiles.iter().filter(|p| p.sub_id == sub.id) {
            print_profile(profile, active == profile.id);
        }
    }
    if store.has_manual() {
        println!("Manual");
        println!(
            "  {}manual{}  {} node(s), psk {}",
            if active == MANUAL_PROFILE_ID { "* " } else { "  " },
            if active == MANUAL_PROFILE_ID { " (active)" } else { "" },
            store.settings.server_urls.len(),
            if store.settings.psk.is_some() { "set" } else { "missing" }
        );
    }
    Ok(())
}

fn print_profile(profile: &spvpn::store::Profile, active: bool) {
    let marker = if active { "* " } else { "  " };
    let suffix = if active { " (active)" } else { "" };
    println!("{marker}{}{suffix}", profile.name);
    let mut overrides = Vec::new();
    if let Some(split) = profile.split {
        overrides.push(format!("split={}", if split { "on" } else { "off" }));
    }
    for (label, value) in [
        ("ru", &profile.route_ru),
        ("non-ru", &profile.route_non_ru),
        ("private", &profile.route_private),
    ] {
        if let Some(value) = value {
            overrides.push(format!("{label}={value}"));
        }
    }
    if !overrides.is_empty() {
        println!("    {}", overrides.join("  "));
    }
}

fn cmd_use(dir: &std::path::Path, needle: &str, json: bool) -> Result<()> {
    let mut store = Store::load(dir)?;
    if needle == MANUAL_PROFILE_ID {
        if !store.has_manual() {
            anyhow::bail!("manual profile is empty: set `spvpn config set urls <url,url>` and `psk`");
        }
        store.active = Some(MANUAL_PROFILE_ID.to_owned());
        store.save(dir)?;
        if json {
            println!("{}", serde_json::json!({"active": MANUAL_PROFILE_ID}));
        } else {
            println!("Active profile: manual");
        }
        return Ok(());
    }
    let profile = store
        .find_profile(needle)
        .with_context(|| format!("profile {needle:?} not found"))?
        .clone();
    store.active = Some(profile.id.clone());
    store.save(dir)?;
    if json {
        println!("{}", serde_json::json!({"active": profile.id, "name": profile.name}));
    } else {
        println!("Active profile: {}", profile.name);
    }
    Ok(())
}

async fn cmd_subs(dir: &std::path::Path, args: SubsArgs, json: bool) -> Result<()> {
    let mut store = Store::load(dir)?;
    match args.cmd {
        SubsCmd::Add { source, name } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?;
            let id = spvpn::subscription::add(&mut store, &source, name, &client).await?;
            store.save(dir)?;
            let profiles = store.profiles.iter().filter(|p| p.sub_id == id).count();
            if json {
                println!("{}", serde_json::json!({"id": id, "profiles": profiles}));
            } else {
                let sub = store.subscriptions.iter().find(|s| s.id == id).unwrap();
                println!("Added subscription {:?}: {} profile(s)", sub.name, profiles);
            }
        }
        SubsCmd::List => {
            if json {
                let list: Vec<_> = store
                    .subscriptions
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "id": s.id, "name": s.name, "source": s.source,
                            "fetched_at": s.fetched_at,
                            "profiles": store.profiles.iter().filter(|p| p.sub_id == s.id).count()
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if store.subscriptions.is_empty() {
                println!("No subscriptions.");
            } else {
                for sub in &store.subscriptions {
                    let profiles = store.profiles.iter().filter(|p| p.sub_id == sub.id).count();
                    println!("{}  {}  ({} profile(s))", sub.id, sub.name, profiles);
                    println!("    {}", sub.source);
                }
            }
        }
        SubsCmd::Remove { id } => {
            if !store.remove_subscription(&id) {
                anyhow::bail!("subscription {id:?} not found");
            }
            store.save(dir)?;
            println!("Removed.");
        }
        SubsCmd::Refresh { id } => {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()?;
            let updated = spvpn::subscription::refresh(&mut store, id.as_deref(), &client).await?;
            store.save(dir)?;
            if json {
                println!("{}", serde_json::json!({"updated": updated}));
            } else {
                println!("Updated {updated} subscription(s).");
            }
        }
    }
    Ok(())
}

async fn cmd_test(dir: &std::path::Path, args: TestArgs, json: bool) -> Result<()> {
    let store = Store::load(dir)?;
    let target = args
        .target
        .unwrap_or_else(|| store.settings.check_url.clone());
    let profiles = if args.all {
        store
            .profiles
            .iter()
            .map(|p| store.resolve(Some(p)))
            .collect::<Result<Vec<_>>>()?
    } else if let Some(needle) = args.profile.as_deref() {
        let profile = if needle == MANUAL_PROFILE_ID {
            None
        } else {
            Some(
                store
                    .find_profile(needle)
                    .with_context(|| format!("profile {needle:?} not found"))?,
            )
        };
        vec![store.resolve(profile)?]
    } else {
        vec![store.resolve(store.active_profile())?]
    };

    if profiles.is_empty() {
        anyhow::bail!("no profiles to test");
    }
    let timeout = Duration::from_secs(args.timeout);
    let cache = dir.join("cache");
    let results = if json {
        spvpn::test_profile::test_many(profiles, cache, target, timeout, args.parallel).await
    } else {
        // Print each result as soon as it arrives instead of waiting for the
        // whole batch; a full run can take minutes when nodes are unreachable.
        spvpn::test_profile::test_many_stream(
            profiles,
            cache,
            target,
            timeout,
            args.parallel,
            |r| {
                if r.ok {
                    println!(
                        "OK   {:<24} {:>6} ms  exit {:<15}  {}",
                        r.profile, r.latency_ms, r.exit_ip, r.route
                    );
                } else {
                    println!(
                        "FAIL {:<24} {:>6} ms  {}  ({})",
                        r.profile, r.latency_ms, r.error, r.route
                    );
                }
            },
        )
        .await
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        let ok = results.iter().filter(|r| r.ok).count();
        println!("\n{ok}/{} profile(s) passed", results.len());
    }
    if results.iter().any(|r| !r.ok) {
        std::process::exit(2);
    }
    Ok(())
}

async fn cmd_status(dir: &std::path::Path, json: bool) -> Result<()> {
    let state = control::read_state(dir).context("client is not running (no state file)")?;
    let reply = control::request(&state.control, serde_json::json!({"cmd": "status"})).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&reply)?);
        return Ok(());
    }
    let status = &reply["status"];
    println!(
        "{}  pid {}  profile {:?}",
        if status["running"].as_bool().unwrap_or(false) {
            "running"
        } else {
            "stopped"
        },
        state.pid,
        status["profile"].as_str().unwrap_or("")
    );
    println!(
        "socks {}   sessions {}   polls {} ({} ok / {} failed)",
        state.socks,
        status["active_sessions"].as_u64().unwrap_or(0),
        status["polls"].as_u64().unwrap_or(0),
        status["poll_ok"].as_u64().unwrap_or(0),
        status["poll_failed"].as_u64().unwrap_or(0)
    );
    println!(
        "traffic: {} up / {} down   uptime {}s",
        human_bytes(status["tx_bytes"].as_u64().unwrap_or(0)),
        human_bytes(status["rx_bytes"].as_u64().unwrap_or(0)),
        status["uptime_s"].as_u64().unwrap_or(0)
    );
    if let Some(err) = status["last_error"].as_str() {
        println!("last error: {err}");
    }
    if let Some(urls) = status["urls"].as_array() {
        for url in urls {
            let q = url["quarantined_s"].as_u64();
            println!(
                "  {}  sessions={} fails={}{}",
                url["url"].as_str().unwrap_or(""),
                url["sessions"].as_u64().unwrap_or(0),
                url["failures"].as_u64().unwrap_or(0),
                q.map(|s| format!("  QUARANTINED {s}s")).unwrap_or_default()
            );
        }
    }
    Ok(())
}

async fn cmd_stop(dir: &std::path::Path) -> Result<()> {
    let state = control::read_state(dir).context("client is not running")?;
    let reply = control::request(&state.control, serde_json::json!({"cmd": "stop"})).await?;
    if reply["ok"].as_bool().unwrap_or(false) {
        println!("Stopping pid {}...", state.pid);
    } else {
        anyhow::bail!("daemon refused to stop: {reply}");
    }
    Ok(())
}

fn cmd_config(dir: &std::path::Path, args: ConfigArgs, json: bool) -> Result<()> {
    let mut store = Store::load(dir)?;
    match args.cmd {
        ConfigCmd::Path => println!("{}", Store::path(dir).display()),
        ConfigCmd::Show => {
            if json {
                println!("{}", serde_json::to_string_pretty(&store)?);
            } else {
                println!("{}", serde_json::to_string_pretty(&store.settings)?);
            }
        }
        ConfigCmd::Set { key, value } => {
            let shown = value.clone();
            let s = &mut store.settings;
            match key.as_str() {
                "socks" | "socks_listen" => s.socks_listen = value,
                "control" | "control_listen" => s.control_listen = value,
                "poll-ms" | "poll_interval_ms" => s.poll_interval_ms = value.parse()?,
                "jitter-ms" | "poll_jitter_ms" => s.poll_jitter_ms = value.parse()?,
                "chunk" | "max_chunk_bytes" => s.max_chunk_bytes = value.parse()?,
                "frames" | "max_frames_per_poll" => s.max_frames_per_poll = value.parse()?,
                "pad" | "pad_polls" => s.pad_polls = parse_bool(&value)?,
                "http2" => s.http2 = parse_bool(&value)?,
                "verify-tls" | "verify_tls" => s.verify_tls = parse_bool(&value)?,
                "selector" => s.selector = value,
                "fail-limit" | "url_fail_limit" => s.url_fail_limit = value.parse()?,
                "cooldown" | "url_cooldown_s" => s.url_cooldown_s = value.parse()?,
                "idle" | "idle_timeout_s" => {
                    s.idle_timeout_s = if value == "0" || value.eq_ignore_ascii_case("off") {
                        None
                    } else {
                        Some(value.parse()?)
                    }
                }
                "psk" => s.psk = Some(value),
                "urls" | "server_urls" => {
                    s.server_urls = value
                        .split(',')
                        .map(|u| u.trim().trim_end_matches('/').to_owned())
                        .filter(|u| !u.is_empty())
                        .collect();
                    if !s.server_urls.is_empty() && store.active.is_none() {
                        store.active = Some(MANUAL_PROFILE_ID.into());
                    }
                }
                "check-url" | "check_url" => s.check_url = value,
                "poll-path" | "poll_path" => s.poll_path = value,
                "host-header" | "host_header" => {
                    s.host_header = if value.is_empty() { None } else { Some(value) }
                }
                "dns-relay" | "dns_relay" => {
                    s.dns_relay = if value.is_empty() { None } else { Some(value) }
                }
                other => anyhow::bail!("unknown setting {other:?}"),
            }
            store.save(dir)?;
            println!("{key} = {shown}");
        }
    }
    Ok(())
}

async fn cmd_logs(dir: &std::path::Path, args: LogsArgs) -> Result<()> {
    let path = spvpn::logging::log_path(dir);
    if !path.exists() {
        println!("No log yet: {}", path.display());
        return Ok(());
    }
    print!("{}", spvpn::logging::tail(dir, args.kb.max(1) * 1024));
    if args.follow {
        let mut offset = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        loop {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            }
            if let Ok(meta) = std::fs::metadata(&path) {
                if meta.len() > offset {
                    use std::io::{Read, Seek, SeekFrom};
                    if let Ok(mut file) = std::fs::File::open(&path) {
                        let _ = file.seek(SeekFrom::Start(offset));
                        let mut buf = String::new();
                        let _ = file.read_to_string(&mut buf);
                        print!("{buf}");
                        offset = meta.len();
                    }
                }
            }
        }
    }
    Ok(())
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_lowercase().as_str() {
        "1" | "true" | "on" | "yes" => Ok(true),
        "0" | "false" | "off" | "no" => Ok(false),
        _ => anyhow::bail!("expected on/off, got {value:?}"),
    }
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut size = value as f64;
    let mut unit = 0;
    while size >= 1024.0 && unit + 1 < UNITS.len() {
        size /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{size:.1} {}", UNITS[unit])
    }
}

#[allow(dead_code)]
fn assert_decision(_: Decision) {}
