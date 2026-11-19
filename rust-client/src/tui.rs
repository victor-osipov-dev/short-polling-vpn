//! Minimal terminal dashboard: live stats, URL health and the log tail.
//!
//! Enabled by the `tui` feature; started automatically on an interactive
//! terminal unless `--no-tui` is passed.

use anyhow::{Context, Result};
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::Notify;

use crate::control::{self, ControlCtx, StateFile};
use crate::store::{Store, MANUAL_PROFILE_ID};
use crate::tunnel::Tunnel;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tab {
    Status,
    Logs,
}

struct Ui {
    tab: Tab,
    scroll: u16,
    auto_scroll: bool,
}

pub async fn run(dir: PathBuf, profile: Option<String>) -> Result<()> {
    let store = Store::load(&dir)?;
    let selected = match profile.as_deref() {
        Some(needle) if needle != MANUAL_PROFILE_ID => Some(
            store
                .find_profile(needle)
                .with_context(|| format!("profile {needle:?} not found"))?
                .clone(),
        ),
        Some(_) => None,
        None => store.active_profile().cloned(),
    };
    let resolved = store.resolve(selected.as_ref())?;
    let socks = resolved.settings.socks_listen.clone();
    let control_addr = resolved.settings.control_listen.clone();

    let tunnel = Tunnel::new(resolved, &dir.join("cache")).await?;
    let handle = tunnel.start();

    let listener = TcpListener::bind(&socks)
        .await
        .with_context(|| format!("cannot bind SOCKS5 listener on {socks}"))?;
    let actual_socks = listener.local_addr()?.to_string();
    let socks_task = tokio::spawn(crate::socks::serve_listener(listener, tunnel.clone()));

    let running = Arc::new(AtomicBool::new(true));
    let shutdown = Arc::new(Notify::new());
    let stopping = Arc::new(AtomicBool::new(false));
    let control_task = {
        let ctx = ControlCtx {
            tunnel: tunnel.clone(),
            socks: actual_socks.clone(),
            shutdown: shutdown.clone(),
            stopping: stopping.clone(),
        };
        let addr = control_addr.clone();
        let flag = running.clone();
        tokio::spawn(async move {
            if let Err(err) = control::serve(addr, ctx, flag).await {
                tracing::error!("control API: {err:#}");
            }
        })
    };

    let state = StateFile {
        pid: std::process::id(),
        socks: actual_socks.clone(),
        control: control_addr.clone(),
        profile: tunnel.profile_name.clone(),
        started_at: crate::subscription::now_secs(),
    };
    control::write_state(&dir, &state)?;

    let mut terminal = ratatui::init();
    let result = event_loop(&mut terminal, &dir, &tunnel, &actual_socks, &control_addr).await;
    ratatui::restore();

    running.store(false, Ordering::Release);
    socks_task.abort();
    control_task.abort();
    handle.stop().await;
    control::clear_state(&dir);
    result
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    dir: &Path,
    tunnel: &Arc<Tunnel>,
    socks: &str,
    control_addr: &str,
) -> Result<()> {
    let mut ui = Ui {
        tab: Tab::Status,
        scroll: 0,
        auto_scroll: true,
    };
    let mut last_rx = 0u64;
    let mut last_tx = 0u64;
    let mut last_sample = Instant::now();
    let mut rx_rate = 0f64;
    let mut tx_rate = 0f64;

    loop {
        if last_sample.elapsed() >= Duration::from_millis(500) {
            let snap = tunnel.snapshot();
            let elapsed = last_sample.elapsed().as_secs_f64().max(0.001);
            rx_rate = (snap.rx_bytes.saturating_sub(last_rx)) as f64 / elapsed;
            tx_rate = (snap.tx_bytes.saturating_sub(last_tx)) as f64 / elapsed;
            last_rx = snap.rx_bytes;
            last_tx = snap.tx_bytes;
            last_sample = Instant::now();
        }

        let snapshot = tunnel.snapshot();
        let logs = if ui.tab == Tab::Logs {
            crate::logging::tail(dir, 48 * 1024)
        } else {
            String::new()
        };
        terminal.draw(|frame| {
            draw(
                frame,
                &ui,
                &snapshot,
                socks,
                control_addr,
                &logs,
                rx_rate,
                tx_rate,
            )
        })?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(())
                    }
                    KeyCode::Tab | KeyCode::Char('1') | KeyCode::Char('2') => {
                        ui.tab = match ui.tab {
                            Tab::Status => Tab::Logs,
                            Tab::Logs => Tab::Status,
                        };
                        ui.scroll = 0;
                        ui.auto_scroll = true;
                    }
                    KeyCode::Down | KeyCode::Char('j') => {
                        ui.scroll = ui.scroll.saturating_add(1);
                        ui.auto_scroll = false;
                    }
                    KeyCode::Up | KeyCode::Char('k') => {
                        ui.scroll = ui.scroll.saturating_sub(1);
                    }
                    KeyCode::End | KeyCode::Char('g') => {
                        ui.auto_scroll = true;
                    }
                    KeyCode::Home => {
                        ui.scroll = 0;
                        ui.auto_scroll = false;
                    }
                    _ => {}
                }
            }
        }
    }
}

fn draw(
    frame: &mut Frame,
    ui: &Ui,
    snapshot: &crate::tunnel::Status,
    socks: &str,
    control: &str,
    logs: &str,
    rx_rate: f64,
    tx_rate: f64,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let title = Line::from(vec![
        Span::styled(
            " Short Polling VPN ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(format!(" {}  ", crate::VERSION)),
        Span::styled(
            if snapshot.running { "running" } else { "stopped" },
            Style::default().fg(if snapshot.running {
                Color::Green
            } else {
                Color::Red
            }),
        ),
        Span::raw(format!(
            "  profile: {}  socks: {}  control: {}",
            snapshot.profile, socks, control
        )),
    ]);
    frame.render_widget(
        Paragraph::new(title).block(Block::default().borders(Borders::BOTTOM)),
        chunks[0],
    );

    match ui.tab {
        Tab::Status => draw_status(frame, ui, snapshot, chunks[1], rx_rate, tx_rate),
        Tab::Logs => draw_logs(frame, ui, logs, chunks[1]),
    }

    let help = Line::from(vec![
        Span::styled("q", Style::default().fg(Color::Yellow)),
        Span::raw(" quit   "),
        Span::styled("tab", Style::default().fg(Color::Yellow)),
        Span::raw(" status/logs   "),
        Span::styled("j/k", Style::default().fg(Color::Yellow)),
        Span::raw(" scroll   "),
        Span::styled("g", Style::default().fg(Color::Yellow)),
        Span::raw(" follow logs"),
    ]);
    frame.render_widget(Paragraph::new(help), chunks[2]);
}

fn draw_status(
    frame: &mut Frame,
    ui: &Ui,
    snapshot: &crate::tunnel::Status,
    area: Rect,
    rx_rate: f64,
    tx_rate: f64,
) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(9), Constraint::Min(3)])
        .split(area);

    let stats = vec![
        Line::from(vec![
            Span::styled("uptime      ", Style::default().fg(Color::DarkGray)),
            Span::raw(format_duration(snapshot.uptime_s)),
        ]),
        Line::from(vec![
            Span::styled("sessions    ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} active / {} total",
                snapshot.active_sessions, snapshot.total_sessions
            )),
        ]),
        Line::from(vec![
            Span::styled("polls       ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} ({} ok / {} failed)",
                snapshot.polls, snapshot.poll_ok, snapshot.poll_failed
            )),
        ]),
        Line::from(vec![
            Span::styled("traffic     ", Style::default().fg(Color::DarkGray)),
            Span::raw(format!(
                "{} down / {} up   ({}/s down, {}/s up)",
                human_bytes(snapshot.rx_bytes),
                human_bytes(snapshot.tx_bytes),
                human_bytes(rx_rate as u64),
                human_bytes(tx_rate as u64),
            )),
        ]),
        Line::from(vec![
            Span::styled("split       ", Style::default().fg(Color::DarkGray)),
            Span::raw(if snapshot.split_enabled { "on" } else { "off" }),
        ]),
        Line::from(vec![
            Span::styled("last error  ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                snapshot.last_error.clone().unwrap_or_else(|| "-".into()),
                Style::default().fg(Color::Red),
            ),
        ]),
        Line::from(vec![
            Span::styled("last poll   ", Style::default().fg(Color::DarkGray)),
            Span::raw(match snapshot.last_poll_age_ms {
                Some(ms) => format!("{ms} ms ago"),
                None => "-".into(),
            }),
        ]),
    ];
    frame.render_widget(
        Paragraph::new(stats).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Activity ")
                .title_style(Style::default().fg(Color::Cyan)),
        ),
        rows[0],
    );

    let lines: Vec<Line> = snapshot
        .urls
        .iter()
        .map(|url| {
            let color = if url.quarantined_s.is_some() {
                Color::Red
            } else if url.failures > 0 {
                Color::Yellow
            } else {
                Color::Green
            };
            Line::from(vec![
                Span::styled("● ", Style::default().fg(color)),
                Span::raw(format!("{:<40}", truncate(&url.url, 40))),
                Span::styled(
                    format!(" sessions {:<3}", url.sessions),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(format!("fails {}", url.failures)),
                Span::styled(
                    match url.quarantined_s {
                        Some(s) => format!("  QUARANTINED {s}s"),
                        None => String::new(),
                    },
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
            ])
        })
        .collect();

    frame.render_widget(
        Paragraph::new(lines)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(format!(" Servers ({}) ", snapshot.urls.len()))
                    .title_style(Style::default().fg(Color::Cyan)),
            )
            .scroll((ui.scroll, 0)),
        rows[1],
    );
}

fn draw_logs(frame: &mut Frame, ui: &Ui, logs: &str, area: Rect) {
    let total = logs.lines().count() as u16;
    let visible = area.height.saturating_sub(2);
    let scroll = if ui.auto_scroll {
        total.saturating_sub(visible)
    } else {
        ui.scroll.min(total.saturating_sub(1))
    };
    let text: Vec<Line> = logs
        .lines()
        .map(|line| {
            let style = if line.contains("ERROR") {
                Style::default().fg(Color::Red)
            } else if line.contains("WARN") {
                Style::default().fg(Color::Yellow)
            } else if line.contains("DEBUG") {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            Line::from(Span::styled(line.to_string(), style))
        })
        .collect();
    frame.render_widget(
        Paragraph::new(text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Logs ")
                    .title_style(Style::default().fg(Color::Cyan)),
            )
            .wrap(Wrap { trim: false })
            .scroll((scroll, 0)),
        area,
    );
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_owned()
    } else {
        let tail: String = value
            .chars()
            .rev()
            .take(max.saturating_sub(1))
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect();
        format!("…{tail}")
    }
}

fn format_duration(secs: u64) -> String {
    let hours = secs / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;
    if hours > 0 {
        format!("{hours}h {minutes:02}m {seconds:02}s")
    } else if minutes > 0 {
        format!("{minutes}m {seconds:02}s")
    } else {
        format!("{seconds}s")
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tunnel::{Status, UrlStatus};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn sample_status() -> Status {
        Status {
            profile: "Relay".into(),
            running: true,
            uptime_s: 75,
            active_sessions: 2,
            total_sessions: 7,
            polls: 42,
            poll_ok: 40,
            poll_failed: 2,
            tx_bytes: 1536,
            rx_bytes: 2 * 1024 * 1024,
            last_error: Some("HTTP 502".into()),
            last_poll_age_ms: Some(120),
            split_enabled: true,
            mode: "socks".into(),
            urls: vec![
                UrlStatus {
                    url: "https://edge.example.com/poll".into(),
                    failures: 0,
                    quarantined_s: None,
                    sessions: 2,
                },
                UrlStatus {
                    url: "https://backup.example.net/poll".into(),
                    failures: 3,
                    quarantined_s: Some(7),
                    sessions: 0,
                },
            ],
        }
    }

    fn render(ui: &Ui, status: &Status, logs: &str) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        terminal
            .draw(|frame| draw(frame, ui, status, "127.0.0.1:1080", "127.0.0.1:1081", logs, 1024.0, 0.0))
            .unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn status_tab_shows_activity_and_servers() {
        let ui = Ui {
            tab: Tab::Status,
            scroll: 0,
            auto_scroll: true,
        };
        let screen = render(&ui, &sample_status(), "");
        assert!(screen.contains("Short Polling VPN"), "{screen}");
        assert!(screen.contains("Relay"), "{screen}");
        assert!(screen.contains("127.0.0.1:1080"), "{screen}");
        assert!(screen.contains("uptime"), "{screen}");
        assert!(screen.contains("1m 15s"), "{screen}");
        assert!(screen.contains("2 active / 7 total"), "{screen}");
        assert!(screen.contains("42 (40 ok / 2 failed)"), "{screen}");
        assert!(screen.contains("2.0 MiB"), "{screen}");
        assert!(screen.contains("HTTP 502"), "{screen}");
        assert!(screen.contains("Servers (2)"), "{screen}");
        assert!(screen.contains("edge.example.com"), "{screen}");
        assert!(screen.contains("QUARANTINED 7s"), "{screen}");
    }

    #[test]
    fn logs_tab_shows_file_tail() {
        let ui = Ui {
            tab: Tab::Logs,
            scroll: 0,
            auto_scroll: true,
        };
        let logs = "2026-01-01 INFO tunnel ready\n2026-01-01 WARN poll failed\n";
        let screen = render(&ui, &sample_status(), logs);
        assert!(screen.contains("tunnel ready"), "{screen}");
        assert!(screen.contains("poll failed"), "{screen}");
        assert!(!screen.contains("Servers (2)"), "{screen}");
    }

    #[test]
    fn helpers_format_compact_values() {
        assert_eq!(format_duration(75), "1m 15s");
        assert_eq!(format_duration(3725), "1h 02m 05s");
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(truncate("short", 10), "short");
        assert!(truncate("https://example.com/very/long/path", 12).starts_with('…'));
    }
}
