//! Minimal desktop UI (egui/eframe).

mod backend;
mod i18n;
mod theme;
mod tray;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use eframe::egui;
use parking_lot::Mutex;

use crate::platform;
use crate::store::{ResolvedProfile, Store, MANUAL_PROFILE_ID};
use crate::test_profile::TestResult;
use crate::tun;
use backend::{Backend, SharedState};
use i18n::Lang;
use tray::{Tray, TrayAction};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Settings,
    Logs,
}

/// Maximum width of the centered content column. Every card fills it, so the
/// blocks share one width and do not stretch across a wide window.
const CONTENT_WIDTH: f32 = 560.0;

/// DoH endpoints offered as one-click presets in the settings.
const DOH_PRESETS: &[(&str, &str)] = &[
    ("Google", "https://8.8.8.8/dns-query"),
    ("Cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("Quad9", "https://9.9.9.9/dns-query"),
];

/// Stable ids for every editable text field, so Ctrl+C/Ctrl+V can find the
/// focused field even though winit does not deliver the usual clipboard events.
const TEXT_SUB_URL: &str = "text-sub-url";
const TEXT_SUB_NAME: &str = "text-sub-name";
const TEXT_CHECK_URL: &str = "text-check-url";
const TEXT_TUN_ADDRESS: &str = "text-tun-address";
const TEXT_TUN_NETMASK: &str = "text-tun-netmask";
const TEXT_TUN_DNS: &str = "text-tun-dns";
const TEXT_TUN_DNS_UPSTREAM: &str = "text-tun-dns-upstream";
const TEXT_TUN_EXCLUDE: &str = "text-tun-exclude";

fn rule_text_id(index: usize) -> egui::Id {
    text_id(&format!("rule-value-{index}"))
}

#[derive(Clone, Copy)]
enum TextTarget {
    SubUrl,
    SubName,
    CheckUrl,
    TunAddress,
    TunNetmask,
    TunDns,
    TunDnsUpstream,
    TunExclude,
    RuleValue(usize),
}

fn text_id(name: &str) -> egui::Id {
    #[allow(deprecated)]
    egui::Id::new(name)
}

fn byte_at_char(text: &str, char_index: usize) -> usize {
    text.char_indices()
        .nth(char_index)
        .map(|(byte, _)| byte)
        .unwrap_or(text.len())
}

fn byte_range(
    text: &str,
    range: egui::text_selection::CCursorRange,
) -> std::ops::Range<usize> {
    let range = range.as_sorted_char_range();
    byte_at_char(text, range.start.0)..byte_at_char(text, range.end.0)
}

fn slice_chars(text: &str, range: egui::text_selection::CCursorRange) -> String {
    let range = byte_range(text, range);
    text[range].to_owned()
}

pub fn run(dir: PathBuf, minimized: bool) -> Result<()> {
    let store = Store::load(&dir).ok();
    let title = if store.as_ref().map(|s| s.settings.ui_language.as_str()) == Some("en") {
        "Internet"
    } else {
        "Интернет"
    };
    let minimized = minimized
        || store
            .as_ref()
            .map(|s| s.settings.ui_start_minimized)
            .unwrap_or(false);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1100.0, 760.0])
            .with_min_inner_size([380.0, 560.0])
            .with_title(title)
            .with_icon(egui::IconData {
                rgba: icon_rgba(64),
                width: 64,
                height: 64,
            })
            .with_visible(!minimized),
        ..Default::default()
    };
    eframe::run_native(
        title,
        options,
        Box::new(move |cc| Ok(Box::new(App::new(cc, dir, minimized)?))),
    )
    .map_err(|err| anyhow::anyhow!("{err}"))
}

struct App {
    dir: PathBuf,
    store: Store,
    lang: Lang,
    page: Page,
    backend: Arc<Backend>,
    shared: Arc<Mutex<SharedState>>,
    tray: Option<Tray>,
    logs: String,
    logs_at: Instant,
    toast: Option<(String, Instant)>,
    add_open: bool,
    /// Focus the URL field as soon as the "new subscription" card opens so
    /// Ctrl+V works without an extra click.
    add_focus_pending: bool,
    new_sub: String,
    new_sub_name: String,
    store_revision: u64,
    /// Reconnect once the current session has finished stopping, e.g. when the
    /// user switches between Proxy and VPN while connected.
    reconnect_after_disconnect: bool,
    refresh_at: Instant,
    was_busy: bool,
    quitting: bool,
    hidden: bool,
    tray_tooltip_at: Instant,
    tray_retry_at: Instant,
    last_shared_running: bool,
    hide_pending: bool,
    hidden_flag: Arc<AtomicBool>,
    /// Dismissed update popup (only for this session).
    update_dismissed: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, dir: PathBuf, minimized: bool) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        theme::apply(&cc.egui_ctx);
        let store = Store::load(&dir)?;
        let lang = Lang::from_code(&store.settings.ui_language);
        let backend = Backend::new(&dir)?;
        if store.settings.ui_check_updates {
            backend.check_updates();
        }
        let shared = backend.shared();
        let tray = Tray::new(lang, false);

        // eframe does not call `ui` while the window is hidden, so keep the
        // logic pass (tray, backend snapshots) alive with a cheap wakeup that
        // only runs while we are actually in the tray.
        let hidden_flag = Arc::new(AtomicBool::new(minimized));
        let waker = cc.egui_ctx.clone();
        let hidden_for_waker = hidden_flag.clone();
        std::thread::Builder::new()
            .name("spvpn-wake".into())
            .spawn(move || loop {
                std::thread::sleep(Duration::from_millis(250));
                if hidden_for_waker.load(Ordering::Relaxed) {
                    waker.request_repaint();
                }
            })
            .ok();

        Ok(Self {
            dir,
            store,
            lang,
            page: Page::Home,
            backend,
            shared,
            tray,
            logs: String::new(),
            logs_at: Instant::now() - Duration::from_secs(5),
            toast: None,
            add_open: false,
            add_focus_pending: false,
            new_sub: String::new(),
            new_sub_name: String::new(),
            store_revision: 0,
            reconnect_after_disconnect: false,
            refresh_at: Instant::now() - Duration::from_secs(2),
            was_busy: false,
            quitting: false,
            hidden: minimized,
            tray_tooltip_at: Instant::now(),
            tray_retry_at: Instant::now() + Duration::from_secs(5),
            last_shared_running: false,
            hide_pending: minimized,
            hidden_flag,
            update_dismissed: false,
        })
    }

    fn tr(&self, ru: &'static str, en: &'static str) -> &'static str {
        self.lang.t(ru, en)
    }

    fn toast(&mut self, text: impl Into<String>) {
        self.toast = Some((text.into(), Instant::now() + Duration::from_secs(4)));
    }

    fn save(&mut self) {
        if let Err(err) = self.store.save(&self.dir) {
            self.toast(format!("{err:#}"));
        }
    }

    fn active_profile_mode(&self) -> String {
        match self.store.active.as_deref() {
            Some(MANUAL_PROFILE_ID) | None => {
                if self.store.settings.manual_mode.eq_ignore_ascii_case("vpn") {
                    "vpn".into()
                } else {
                    "proxy".into()
                }
            }
            Some(id) => self
                .store
                .profiles
                .iter()
                .find(|p| p.id == id)
                .map(|p| p.mode.clone())
                .unwrap_or_else(|| "proxy".into()),
        }
    }

    fn set_active_mode(&mut self, mode: &str) {
        match self.store.active.as_deref() {
            Some(MANUAL_PROFILE_ID) | None => {
                self.store.settings.manual_mode = mode.into();
            }
            Some(id) => {
                if let Some(profile) = self.store.profiles.iter_mut().find(|p| p.id == id) {
                    profile.mode = mode.into();
                }
            }
        }
        self.save();

        // The mode is read when a session starts, so switching it while
        // connected must restart the session to actually take effect.
        let (running, busy) = {
            let shared = self.shared.lock();
            (shared.running, shared.busy)
        };
        if running && !busy {
            self.reconnect_after_disconnect = true;
            self.disconnect();
            self.toast(self.tr(
                "Переподключение в новом режиме…",
                "Reconnecting in the new mode…",
            ));
        }
    }

    fn active_resolved(&self) -> Result<ResolvedProfile> {
        let profile = match self.store.active.as_deref() {
            Some(MANUAL_PROFILE_ID) | None => None,
            Some(id) => self.store.find_profile(id),
        };
        self.store.resolve(profile)
    }

    fn connect(&mut self) {
        let resolved = match self.active_resolved() {
            Ok(resolved) => resolved,
            Err(err) => {
                self.toast(format!("{err:#}"));
                return;
            }
        };
        if !self.backend.connect(resolved) {
            self.toast(self.tr(
                "Подключение уже выполняется",
                "Connection is already busy",
            ));
        }
    }

    fn disconnect(&mut self) {
        self.backend.disconnect();
    }

    fn apply_store_revision(&mut self) {
        let revision = self.shared.lock().store_revision;
        if revision != self.store_revision {
            self.store_revision = revision;
            match Store::load(&self.dir) {
                Ok(store) => {
                    self.store = store;
                    self.lang = Lang::from_code(&self.store.settings.ui_language);
                }
                Err(err) => self.toast(format!("{err:#}")),
            }
        }
    }

    fn test_profiles(&mut self, all: bool, one: Option<&str>) {
        let target = self.store.settings.check_url.clone();
        let profiles = if all {
            self.store
                .profiles
                .iter()
                .filter_map(|p| self.store.resolve(Some(p)).ok())
                .collect::<Vec<_>>()
        } else if let Some(id) = one {
            let profile = if id == MANUAL_PROFILE_ID {
                None
            } else {
                self.store.find_profile(id)
            };
            match self.store.resolve(profile) {
                Ok(p) => vec![p],
                Err(err) => {
                    self.toast(format!("{err:#}"));
                    return;
                }
            }
        } else {
            return;
        };
        self.backend.test_profiles(profiles, target);
    }

    fn refresh_logs(&mut self, force: bool) {
        if force || self.logs_at.elapsed() > Duration::from_secs(1) {
            self.logs = crate::logging::tail(&self.dir, 256 * 1024);
            self.logs_at = Instant::now();
        }
    }

    /// Retry tray creation with a back-off and never leave the app invisible
    /// with no tray entry point (for example when started with `--minimized`).
    fn ensure_tray(&mut self, ctx: &egui::Context) {
        self.hidden_flag.store(self.hidden, Ordering::Relaxed);
        if self.tray.is_none() && Instant::now() >= self.tray_retry_at {
            self.tray_retry_at = Instant::now() + Duration::from_secs(5);
            self.tray = Tray::new(self.lang, self.last_shared_running);
            if self.tray.is_some() {
                self.tray_tooltip_at = Instant::now() - Duration::from_secs(2);
            }
        }
        if self.hidden && self.tray.is_none() {
            self.hidden = false;
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        }
        if self.hidden && self.tray.is_some() {
            if self.hide_pending {
                // The first painted frame is forced visible by eframe; hide
                // on the next logic pass once that frame is on screen.
                self.hide_pending = false;
                ctx.request_repaint();
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
    }

    fn update_tray(&mut self, ctx: &egui::Context) {
        let Some(actions) = self.tray.as_ref().map(|tray| tray.poll()) else {
            return;
        };
        for action in actions {
            match action {
                TrayAction::Show => {
                    self.hidden = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                TrayAction::Connect => {
                    if !self.shared.lock().running {
                        self.connect();
                    }
                }
                TrayAction::Disconnect => self.disconnect(),
                TrayAction::Quit => {
                    self.quitting = true;
                    self.backend.disconnect_blocking();
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
            }
        }
        if self.tray_tooltip_at.elapsed() > Duration::from_secs(1) {
            self.tray_tooltip_at = Instant::now();
            let shared = self.shared.lock();
            let text = if shared.disconnecting {
                self.tr("Интернет — отключение…", "Internet — disconnecting…")
            } else if shared.running {
                self.tr("Интернет — подключено", "Internet — connected")
            } else if shared.busy {
                self.tr("Интернет — подключение…", "Internet — connecting…")
            } else {
                self.tr("Интернет", "Internet")
            };
            if let Some(tray) = &self.tray {
                tray.set_tooltip(text);
            }
        }
    }

    fn handle_close(&mut self, ctx: &egui::Context) {
        if !ctx.input(|i| i.viewport().close_requested()) {
            return;
        }
        if self.quitting {
            self.backend.disconnect_blocking();
            return;
        }
        if self.store.settings.ui_close_to_tray && self.tray.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            self.hidden = true;
        } else {
            self.backend.disconnect_blocking();
        }
    }

    fn elevate(&mut self) {
        self.backend.disconnect_blocking();
        let dir = self.dir.to_string_lossy().into_owned();
        match tun::relaunch_elevated(&["--dir".into(), dir]) {
            Ok(()) => {
                self.quitting = true;
                std::process::exit(0);
            }
            Err(err) => self.toast(format!("{err:#}")),
        }
    }

    fn header(&mut self, root: &mut egui::Ui) {
        egui::Panel::top("header")
            .exact_size(54.0)
            .frame(
                egui::Frame::NONE
                    .fill(theme::HEADER)
                    .stroke(egui::Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin::symmetric(20, 8)),
            )
            .show(root, |ui| {
                // Keep the navigation untouched; drop the title/version when
                // the window is too narrow to fit both without overlapping.
                let show_title = ui.available_width() >= 780.0;
                ui.horizontal(|ui| {
                    if show_title {
                        ui.label(
                            egui::RichText::new(self.tr("Интернет", "Internet"))
                                .size(18.0)
                                .strong(),
                        );
                        ui.add_space(4.0);
                        ui.label(
                            egui::RichText::new(format!("v{}", crate::VERSION))
                                .size(11.0)
                                .color(theme::MUTED),
                        );
                        ui.add_space(8.0);
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::nav_button(ui, "EN", self.lang == Lang::En) {
                            self.lang = Lang::En;
                            self.store.settings.ui_language = "en".into();
                            self.save();
                            self.tray = Tray::new(self.lang, self.shared.lock().running);
                        }
                        if theme::nav_button(ui, "RU", self.lang == Lang::Ru) {
                            self.lang = Lang::Ru;
                            self.store.settings.ui_language = "ru".into();
                            self.save();
                            self.tray = Tray::new(self.lang, self.shared.lock().running);
                        }
                        ui.add_space(8.0);
                        self.nav_button(ui, Page::Logs, self.tr("Логи", "Logs"));
                        self.nav_button(ui, Page::Settings, self.tr("Настройки", "Settings"));
                        self.nav_button(ui, Page::Home, self.tr("Главная", "Home"));
                    });
                });
            });
    }

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, text: &str) {
        if theme::nav_button(ui, text, self.page == page) {
            self.page = page;
        }
    }

    fn home(&mut self, ui: &mut egui::Ui) {
        let shared = self.shared.lock().clone();
        let running = shared.running;
        let busy = shared.busy;
        let disconnecting = shared.disconnecting;
        let status = shared.status.clone();
        let error = shared.error.clone();

        egui::Frame::NONE
            .fill(theme::CARD)
            .stroke(egui::Stroke::new(1.0, theme::BORDER))
            .corner_radius(18)
            .inner_margin(egui::Margin::symmetric(18, 16))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    let color = if disconnecting {
                        theme::AMBER
                    } else if running {
                        theme::GREEN
                    } else {
                        theme::MUTED
                    };
                    let pill_text = if disconnecting {
                            format!("● {}", self.tr("Отключение", "Disconnecting"))
                        } else if running {
                            format!("● {}", self.tr("Подключено", "Connected"))
                        } else if busy {
                            format!("● {}", self.tr("Подключение", "Connecting"))
                    } else {
                        format!("● {}", self.tr("Отключено", "Disconnected"))
                    };
                    theme::pill(ui, &pill_text, color);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mode = self.active_profile_mode();
                        if theme::nav_button(ui, self.tr("Прокси", "Proxy"), mode == "proxy") {
                            self.set_active_mode("proxy");
                        }
                        if theme::nav_button(ui, "VPN", mode == "vpn") {
                            self.set_active_mode("vpn");
                        }
                    });
                });
                ui.add_space(10.0);
                let profile = status
                    .as_ref()
                    .map(|s| s.profile.clone())
                    .or_else(|| {
                        self.store
                            .active_profile()
                            .map(|p| p.name.clone())
                            .or_else(|| {
                                (self.store.active.as_deref() == Some(MANUAL_PROFILE_ID))
                                    .then(|| "Manual".to_owned())
                            })
                    })
                    .unwrap_or_else(|| self.tr("Нет профиля", "No profile").to_owned());
                ui.label(
                    egui::RichText::new(format!("[{}]  {}", country_code(&profile), profile))
                        .size(21.0)
                        .strong(),
                );
                let subtitle: String = if disconnecting {
                    self.tr("Отключение…", "Disconnecting…").to_owned()
                } else if running {
                    if shared.tun_active {
                        self.tr("Весь трафик идёт через VPN", "All traffic is routed through the VPN").to_owned()
                    } else if self.store.settings.system_proxy {
                        let addr = shared.http_proxy.as_deref().unwrap_or("");
                        format!("{} · http://{addr}", self.tr("Системный прокси", "System proxy"))
                    } else {
                        self.tr(
                            "Системный прокси выключен в настройках",
                            "System proxy is disabled in settings",
                        )
                        .to_owned()
                    }
                } else {
                    self.tr(
                        "Выберите профиль и нажмите «Подключить»",
                        "Pick a profile and press Connect",
                    )
                    .to_owned()
                };
                theme::hint(ui, &subtitle);
                ui.add_space(14.0);

                let (fill, label, color) = if disconnecting {
                    (
                        theme::AMBER.gamma_multiply(0.18),
                        self.tr("Отключение…", "Disconnecting…"),
                        theme::AMBER,
                    )
                } else if running {
                    (
                        theme::RED.gamma_multiply(0.18),
                        self.tr("Отключить", "Disconnect"),
                        theme::RED,
                    )
                } else if busy {
                    (
                        theme::CARD_HOVER,
                        self.tr("Подключение…", "Connecting…"),
                        theme::TEXT,
                    )
                } else {
                    (
                        theme::ACCENT.gamma_multiply(0.22),
                        self.tr("Подключить", "Connect"),
                        theme::TEXT,
                    )
                };
                let button = egui::Button::new(
                    egui::RichText::new(label)
                        .size(17.0)
                        .strong()
                        .color(color),
                )
                .fill(fill)
                .stroke(egui::Stroke::new(
                    1.0,
                    if !running && !disconnecting {
                        theme::ACCENT
                    } else {
                        color
                    },
                ))
                .corner_radius(14)
                .min_size(egui::vec2(ui.available_width(), 56.0));
                if ui.add_enabled(!busy, button).clicked() {
                    if running {
                        self.disconnect();
                    } else {
                        self.connect();
                    }
                }

                if let Some(err) = error {
                    ui.add_space(8.0);
                    let text = if err == "vpn_needs_admin" {
                        self.tr(
                            "Для VPN-режима нужны права администратора",
                            "VPN mode requires Administrator rights",
                        )
                        .to_owned()
                    } else {
                        err
                    };
                    egui::Frame::NONE
                        .fill(theme::RED.gamma_multiply(0.12))
                        .corner_radius(10)
                        .inner_margin(egui::Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.label(egui::RichText::new(text).size(12.0).color(theme::RED));
                            if ui
                                .small_button(self.tr(
                                    "Перезапустить от администратора",
                                    "Restart as Administrator",
                                ))
                                .clicked()
                            {
                                self.elevate();
                            }
                        });
                }
            });

        ui.add_space(10.0);
        if let Some(status) = &status {
            self.stats(ui, status, &shared);
        }

        ui.add_space(10.0);
        self.subscriptions(ui);
    }

    fn stats(&self, ui: &mut egui::Ui, status: &crate::tunnel::Status, shared: &SharedState) {
        theme::card_ui(ui, |ui| {
            let rect = ui.available_rect_before_wrap();
            ui.columns(3, |cols| {
                self.stat(
                    &mut cols[0],
                    self.tr("Задержка", "Latency"),
                    &status
                        .avg_latency_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "—".into()),
                );
                self.stat(
                    &mut cols[1],
                    self.tr("Трафик", "Traffic"),
                    &format!(
                        "↑{} ↓{}",
                        human_bytes(status.tx_bytes),
                        human_bytes(status.rx_bytes)
                    ),
                );
                self.stat(
                    &mut cols[2],
                    self.tr("Время", "Uptime"),
                    &format_duration(status.uptime_s),
                );
            });
            let bottom = ui.cursor().min.y.max(rect.min.y + 40.0);
            for i in 1..3 {
                let x = rect.left() + rect.width() * (i as f32 / 3.0);
                ui.painter().vline(
                    x,
                    rect.min.y..=bottom,
                    egui::Stroke::new(1.0, egui::Color32::from_rgb(58, 72, 92)),
                );
            }
            if !shared.exit_ip.is_empty() {
                ui.add_space(6.0);
                theme::hint(ui, &format!("exit IP: {}", shared.exit_ip));
            }
            if let Some(err) = &status.last_error {
                ui.add_space(6.0);
                ui.label(
                    egui::RichText::new(err)
                        .size(11.0)
                        .color(theme::AMBER),
                );
            }
        });
    }

    fn stat(&self, ui: &mut egui::Ui, label: &str, value: &str) {
        ui.vertical_centered(|ui| {
            ui.label(egui::RichText::new(value).size(14.0).strong());
            theme::hint(ui, label);
        });
    }

    fn subscriptions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(self.tr("Профили", "Profiles")).size(16.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if theme::tool_button(ui, &self.tr("+ Подписка", "+ Subscription")) {
                    self.add_open = !self.add_open;
                    self.add_focus_pending = self.add_open;
                }
                if theme::tool_button(ui, &self.tr("Обновить", "Refresh")) {
                    self.backend.refresh_subscriptions();
                    self.toast(self.tr("Обновление подписок…", "Refreshing subscriptions…"));
                }
                if theme::tool_button(ui, self.tr("Тест всех", "Test all")) {
                    self.test_profiles(true, None);
                    ui.ctx().request_repaint();
                }
            });
        });
        ui.add_space(4.0);

        if self.add_open {
            theme::card_ui(ui, |ui| {
                ui.label(egui::RichText::new(self.tr("Новая подписка", "New subscription")).strong());
                let url_field = ui.add(
                    egui::TextEdit::singleline(&mut self.new_sub)
                        .id(text_id(TEXT_SUB_URL))
                        .hint_text("https://example/subscription.json")
                        .desired_width(f32::INFINITY),
                );
                if self.add_focus_pending {
                    url_field.request_focus();
                    self.add_focus_pending = false;
                }
                let name_hint = self.tr("Название (необязательно)", "Name (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_sub_name)
                        .id(text_id(TEXT_SUB_NAME))
                        .hint_text(name_hint)
                        .desired_width(f32::INFINITY),
                );
                ui.horizontal(|ui| {
                    let add = ui.add_enabled(
                        !self.new_sub.trim().is_empty(),
                        egui::Button::new(self.tr("Добавить", "Add")),
                    );
                    if add.clicked() {
                        let source = std::mem::take(&mut self.new_sub);
                        let name = if self.new_sub_name.trim().is_empty() {
                            None
                        } else {
                            Some(std::mem::take(&mut self.new_sub_name))
                        };
                        self.backend.add_subscription(source, name);
                        self.add_open = false;
                        self.add_focus_pending = false;
                    }
                    if ui.button(self.tr("Вставить", "Paste")).clicked() {
                        if let Some(text) = platform::clipboard_text() {
                            self.new_sub = text.trim().to_owned();
                        }
                        url_field.request_focus();
                    }
                    if ui.button(self.tr("Отмена", "Cancel")).clicked() {
                        self.add_open = false;
                        self.add_focus_pending = false;
                    }
                });
            });
            ui.add_space(6.0);
        }

        let active = self.store.active.clone().unwrap_or_default();
        let subs: Vec<(String, String, String)> = self
            .store
            .subscriptions
            .iter()
            .map(|s| (s.id.clone(), s.name.clone(), s.source.clone()))
            .collect();
        let (tests, pending) = {
            let shared = self.shared.lock();
            (shared.tests.clone(), shared.test_pending.clone())
        };
        let mut select: Option<String> = None;
        let mut test: Option<String> = None;
        let mut remove: Option<String> = None;

        for (sub_id, sub_name, source) in subs {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(egui::RichText::new(sub_name).strong());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if theme::danger_button(ui, self.tr("Удалить", "Remove")) {
                        remove = Some(sub_id.clone());
                    }
                });
            });
            theme::hint(ui, &source);
            let rows: Vec<(String, String)> = self
                .store
                .profiles
                .iter()
                .filter(|p| p.sub_id == sub_id)
                .map(|p| (p.id.clone(), p.name.clone()))
                .collect();
            if rows.is_empty() {
                theme::hint(ui, self.tr("Нет профилей", "No profiles"));
            }
            for (id, name) in rows {
                self.profile_row(
                    ui,
                    &id,
                    &name,
                    &name,
                    &active,
                    &tests,
                    &pending,
                    &mut select,
                    &mut test,
                );
            }
        }

        if self.store.has_manual() {
            ui.add_space(6.0);
            ui.label(egui::RichText::new("Manual").strong());
            self.profile_row(
                ui,
                MANUAL_PROFILE_ID,
                self.tr("Ручной профиль", "Manual profile"),
                "Manual",
                &active,
                &tests,
                &pending,
                &mut select,
                &mut test,
            );
        }

        if self.store.subscriptions.is_empty() && !self.store.has_manual() {
            theme::hint(
                ui,
                self.tr(
                    "Добавьте подписку, чтобы начать.",
                    "Add a subscription to get started.",
                ),
            );
        }

        if let Some(id) = select {
            self.store.active = Some(id);
            self.save();
        }
        if let Some(id) = test {
            self.test_profiles(false, Some(&id));
            ui.ctx().request_repaint();
        }
        if let Some(id) = remove {
            self.store.remove_subscription(&id);
            self.save();
        }
    }

    fn profile_row(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        name: &str,
        test_key: &str,
        active: &str,
        tests: &[TestResult],
        pending: &[String],
        select: &mut Option<String>,
        test: &mut Option<String>,
    ) {
        let checking = pending.iter().any(|item| item == test_key);
        let result = tests.iter().find(|r| r.profile == test_key);
        let mut test_rect: Option<egui::Rect> = None;
        let mut test_clicked = false;
        let mut row_clicked = false;
        let inner = egui::Frame::NONE
            .fill(if id == active {
                theme::ACCENT.gamma_multiply(0.08)
            } else {
                theme::CARD
            })
            .stroke(egui::Stroke::new(
                1.0,
                if id == active { theme::ACCENT } else { theme::BORDER },
            ))
            .corner_radius(12)
            .inner_margin(egui::Margin::symmetric(12, 8))
            .show(ui, |ui| {
                ui.set_min_width(ui.available_width());
                ui.horizontal(|ui| {
                    if ui.radio(id == active, "").clicked() {
                        row_clicked = true;
                    }
                    if ui
                        .add(
                            egui::Label::new(egui::RichText::new(name).strong())
                                .sense(egui::Sense::click()),
                        )
                        .clicked()
                    {
                        row_clicked = true;
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let test_button = theme::tool_button_response(ui, self.tr("Тест", "Test"));
                        test_rect = Some(test_button.rect);
                        if test_button.clicked() {
                            test_clicked = true;
                            *test = Some(id.to_owned());
                        }
                        if checking {
                            ui.add(egui::Spinner::new().size(12.0));
                            theme::pill(ui, self.tr("Проверка…", "Checking…"), theme::ACCENT);
                        } else if let Some(result) = result {
                            if result.ok {
                                theme::pill(
                                    ui,
                                    &format!("{} ms", result.latency_ms),
                                    theme::GREEN,
                                );
                            } else {
                                theme::pill(ui, "FAIL", theme::RED);
                            }
                        }
                    });
                });
                if !checking {
                    if let Some(result) = result {
                        let hint = if !result.ok {
                            Some(result.error.clone())
                        } else if !result.exit_ip.is_empty() {
                            Some(format!("exit {}", result.exit_ip))
                        } else {
                            None
                        };
                        if let Some(hint) = hint {
                            if ui
                                .add(
                                    egui::Label::new(
                                        egui::RichText::new(hint).size(11.0).color(theme::MUTED),
                                    )
                                    .sense(egui::Sense::click()),
                                )
                                .clicked()
                            {
                                row_clicked = true;
                            }
                        }
                    }
                }
            });
        // Register ONE click area over the whole card, after its content, so
        // empty space anywhere in the card (including the bottom) is covered.
        // The Test button is excluded by pointer position.
        let card_click = ui.interact(
            inner.response.rect,
            text_id(&format!("profile-select-{id}")),
            egui::Sense::click(),
        );
        if card_click.clicked() || row_clicked {
            let test_hit = card_click
                .interact_pointer_pos()
                .and_then(|pos| test_rect.map(|rect| rect.contains(pos)))
                .unwrap_or(false);
            if test_hit || test_clicked {
                *test = Some(id.to_owned());
            } else {
                *select = Some(id.to_owned());
            }
        }
        ui.add_space(2.0);
    }

    fn settings(&mut self, ui: &mut egui::Ui) {
        let mut changed = false;
        theme::section_title(ui, self.tr("Интерфейс", "Interface"));
        theme::card_ui(ui, |ui| {
            egui::Grid::new("ui_settings")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(self.tr("Язык", "Language"));
                    egui::ComboBox::from_id_salt("lang")
                        .selected_text(if self.lang == Lang::Ru { "Русский" } else { "English" })
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(self.lang == Lang::Ru, "Русский").clicked() {
                                self.lang = Lang::Ru;
                                self.store.settings.ui_language = "ru".into();
                                changed = true;
                            }
                            if ui.selectable_label(self.lang == Lang::En, "English").clicked() {
                                self.lang = Lang::En;
                                self.store.settings.ui_language = "en".into();
                                changed = true;
                            }
                        });
                    ui.end_row();
                    ui.label(self.tr("Автозапуск", "Start with Windows"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.ui_autostart, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Сворачивать в трей", "Close to tray"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.ui_close_to_tray, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Запускать свёрнутым", "Start minimized"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.ui_start_minimized, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Системный прокси", "System proxy"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.system_proxy, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Проверять обновления", "Check for updates"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.ui_check_updates, "")
                        .changed();
                    ui.end_row();
                });
        });

        ui.add_space(10.0);
        theme::section_title(ui, self.tr("Соединение", "Connection"));
        theme::card_ui(ui, |ui| {
            egui::Grid::new("conn_settings")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(self.tr("Интервал, мс", "Interval, ms"));
                    changed |= ui
                        .add(
                            egui::DragValue::new(&mut self.store.settings.poll_interval_ms)
                                .range(50..=5000),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Простой, мс", "Idle, ms"));
                    changed |= ui
                        .add(
                            egui::DragValue::new(&mut self.store.settings.poll_idle_ms)
                                .range(100..=15000),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Минимум, мс", "Minimum, ms"));
                    changed |= ui
                        .add(
                            egui::DragValue::new(&mut self.store.settings.poll_min_ms)
                                .range(20..=1000),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Джиттер, мс", "Jitter, ms"));
                    changed |= ui
                        .add(
                            egui::DragValue::new(&mut self.store.settings.poll_jitter_ms)
                                .range(0..=1000),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Выбор узла", "Node selector"));
                    egui::ComboBox::from_id_salt("selector")
                        .selected_text(&self.store.settings.selector)
                        .show_ui(ui, |ui| {
                            changed |= ui
                                .selectable_value(
                                    &mut self.store.settings.selector,
                                    "random".into(),
                                    "random",
                                )
                                .changed();
                            changed |= ui
                                .selectable_value(
                                    &mut self.store.settings.selector,
                                    "round".into(),
                                    "round",
                                )
                                .changed();
                        });
                    ui.end_row();
                    ui.label("HTTP/2");
                    changed |= ui.checkbox(&mut self.store.settings.http2, "").changed();
                    ui.end_row();
                    ui.label(self.tr("Проверять TLS", "Verify TLS"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.verify_tls, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Паддинг", "Pad polls"));
                    changed |= ui
                        .checkbox(&mut self.store.settings.pad_polls, "")
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Idle timeout, с", "Idle timeout, s"));
                    let mut enabled = self.store.settings.idle_timeout_s.is_some();
                    if ui.checkbox(&mut enabled, "").changed() {
                        self.store.settings.idle_timeout_s = enabled.then_some(300);
                        changed = true;
                    }
                    if let Some(timeout) = self.store.settings.idle_timeout_s.as_mut() {
                        changed |= ui
                            .add(egui::DragValue::new(timeout).range(30..=86_400))
                            .changed();
                    }
                    ui.end_row();
                    ui.label(self.tr("Check URL", "Check URL"));
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.check_url)
                                .id(text_id(TEXT_CHECK_URL))
                                .desired_width(260.0),
                        )
                        .changed();
                    ui.end_row();
                });
        });

        ui.add_space(10.0);
        theme::section_title(ui, "VPN (TUN)");
        theme::card_ui(ui, |ui| {
            let admin = platform::is_elevated();
            ui.horizontal(|ui| {
                theme::pill(
                    ui,
                    if admin {
                        self.tr("АДМИНИСТРАТОР", "ADMINISTRATOR")
                    } else {
                        self.tr("НЕТ ПРАВ", "NOT ELEVATED")
                    },
                    if admin { theme::GREEN } else { theme::AMBER },
                );
                if !admin
                    && ui
                        .small_button(self.tr(
                            "Перезапустить от администратора",
                            "Restart as Administrator",
                        ))
                        .clicked()
                {
                    self.elevate();
                }
            });
            ui.add_space(4.0);
            egui::Grid::new("tun_settings")
                .num_columns(2)
                .spacing([12.0, 8.0])
                .show(ui, |ui| {
                    ui.label(self.tr("Адрес", "Address"));
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_address)
                                .id(text_id(TEXT_TUN_ADDRESS))
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Маска", "Netmask"));
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_netmask)
                                .id(text_id(TEXT_TUN_NETMASK))
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label("DNS");
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_dns)
                                .id(text_id(TEXT_TUN_DNS))
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label("MTU");
                    changed |= ui
                        .add(egui::DragValue::new(&mut self.store.settings.tun_mtu).range(576..=9000))
                        .changed();
                    ui.end_row();
                    ui.label("DNS-over-HTTPS");
                    let mut doh = self.store.settings.doh_enabled();
                    if ui.checkbox(&mut doh, "").changed() {
                        let previous = self.store.settings.tun_dns_upstream.trim().to_owned();
                        if doh {
                            if !previous.is_empty()
                                && !previous.to_ascii_lowercase().starts_with("https://")
                            {
                                self.store.settings.tun_udp_upstream = previous;
                            }
                            let url = self.store.settings.tun_doh_url.trim().to_owned();
                            self.store.settings.tun_dns_upstream = if url.is_empty() {
                                crate::store::DEFAULT_DOH_URL.to_owned()
                            } else {
                                url
                            };
                        } else {
                            if previous.to_ascii_lowercase().starts_with("https://") {
                                self.store.settings.tun_doh_url = previous;
                            }
                            let udp = self.store.settings.tun_udp_upstream.trim().to_owned();
                            self.store.settings.tun_dns_upstream =
                                if udp.is_empty() || udp.starts_with("https://") {
                                    crate::store::DEFAULT_UDP_UPSTREAM.to_owned()
                                } else {
                                    udp
                                };
                        }
                        changed = true;
                    }
                    ui.end_row();
                    ui.label(self.tr("DNS-сервер", "DNS upstream"));
                    let dns_edit = ui.add(
                        egui::TextEdit::singleline(&mut self.store.settings.tun_dns_upstream)
                            .id(text_id(TEXT_TUN_DNS_UPSTREAM))
                            .hint_text(if doh {
                                "https://8.8.8.8/dns-query"
                            } else {
                                "1.1.1.1:53"
                            })
                            .desired_width(180.0),
                    );
                    if dns_edit.changed() {
                        changed = true;
                        if self.store.settings.doh_enabled() {
                            self.store.settings.tun_doh_url =
                                self.store.settings.tun_dns_upstream.clone();
                        } else {
                            self.store.settings.tun_udp_upstream =
                                self.store.settings.tun_dns_upstream.clone();
                        }
                    }
                    ui.end_row();
                    if self.store.settings.doh_enabled() {
                        ui.label(self.tr("DoH-провайдер", "DoH provider"));
                        let current = self.store.settings.tun_dns_upstream.trim().to_owned();
                        let selected = DOH_PRESETS
                            .iter()
                            .find(|(_, url)| *url == current.as_str())
                            .map(|(name, _)| *name)
                            .unwrap_or_else(|| self.tr("Свой", "Custom"));
                        egui::ComboBox::from_id_salt("doh_preset")
                            .selected_text(selected)
                            .width(180.0)
                            .show_ui(ui, |ui| {
                                for (name, url) in DOH_PRESETS {
                                    if ui
                                        .selectable_label(current.as_str() == *url, *name)
                                        .clicked()
                                    {
                                        self.store.settings.tun_dns_upstream = (*url).to_owned();
                                        self.store.settings.tun_doh_url = (*url).to_owned();
                                        changed = true;
                                    }
                                }
                            });
                        ui.end_row();
                    }
                    ui.label(self.tr("Исключения", "Exclusions"));
                    let mut text = self.store.settings.tun_exclude.join(", ");
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut text)
                                .id(text_id(TEXT_TUN_EXCLUDE))
                                .hint_text("1.2.3.4, 5.6.7.8")
                                .desired_width(220.0),
                        )
                        .changed()
                    {
                        self.store.settings.tun_exclude = text
                            .split([',', ' ', ';'])
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect();
                        changed = true;
                    }
                    ui.end_row();
                });
            ui.add_space(4.0);
            theme::hint(
                ui,
                self.tr(
                    "DoH и правила маршрутизации применяются после переподключения.",
                    "DoH and routing rules apply after reconnecting.",
                ),
            );
        });

        ui.add_space(10.0);
        self.routing_rules(ui, &mut changed);

        ui.add_space(10.0);
        self.split_settings(ui, &mut changed);

        ui.add_space(10.0);
        self.url_settings(ui, &mut changed);

        ui.add_space(10.0);
        theme::section_title(ui, self.tr("Подписки", "Subscriptions"));
        theme::card_ui(ui, |ui| {
            if self.store.subscriptions.is_empty() {
                theme::hint(ui, self.tr("Подписок пока нет.", "No subscriptions yet."));
            }
            let subs: Vec<(String, String, String)> = self
                .store
                .subscriptions
                .iter()
                .map(|s| (s.id.clone(), s.name.clone(), s.source.clone()))
                .collect();
            for (id, name, source) in subs {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(name).strong());
                        theme::hint(ui, &source);
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::danger_button(ui, self.tr("Удалить", "Remove")) {
                            self.store.remove_subscription(&id);
                            changed = true;
                        }
                    });
                });
            }
            ui.add_space(4.0);
            if theme::tool_button(ui, self.tr("Обновить все", "Refresh all")) {
                self.backend.refresh_subscriptions();
            }
        });

        if changed {
            self.save();
            if self.store.settings.ui_autostart != platform::autostart_enabled() {
                if let Err(err) = platform::set_autostart(self.store.settings.ui_autostart) {
                    self.toast(format!("{err:#}"));
                }
            }
        }
    }

    /// Editor for the ordered custom routing rules. The list is global (not
    /// per profile) and is evaluated before the split routing below.
    fn routing_rules(&mut self, ui: &mut egui::Ui, changed: &mut bool) {
        let lang = self.lang;
        theme::section_title(ui, lang.t("Правила маршрутизации", "Routing rules"));
        let routes = self.store.route_names();
        let mut remove: Option<usize> = None;
        let mut move_up: Option<usize> = None;
        let mut move_down: Option<usize> = None;
        theme::card_ui(ui, |ui| {
            theme::hint(
                ui,
                lang.t(
                    "Проверяются сверху вниз, первое совпадение выигрывает. Если ни одно правило не совпало, работает раздельное маршрутизирование ниже.",
                    "Checked top to bottom; the first match wins. If nothing matches, split routing below applies.",
                ),
            );
            theme::hint(
                ui,
                lang.t(
                    "Правила по процессу работают в режиме VPN при выключенном системном прокси.",
                    "Process rules work in VPN mode with the system proxy off.",
                ),
            );
            ui.add_space(4.0);
            let count = self.store.settings.routing_rules.len();
            for i in 0..count {
                {
                    let rule = &mut self.store.settings.routing_rules[i];
                    ui.horizontal(|ui| {
                        *changed |= ui.checkbox(&mut rule.enabled, "").changed();
                        egui::ComboBox::from_id_salt(("rule_kind", i))
                            .width(108.0)
                            .selected_text(kind_label(&rule.kind, lang))
                            .show_ui(ui, |ui| {
                                for (value, ru, en) in [
                                    ("process", "Процесс", "Process"),
                                    ("domain", "Домен", "Domain"),
                                    ("ip", "IP / CIDR", "IP / CIDR"),
                                    ("all", "Всё", "All"),
                                ] {
                                    if ui
                                        .selectable_label(rule.kind == value, lang.t(ru, en))
                                        .clicked()
                                    {
                                        rule.kind = value.to_owned();
                                        *changed = true;
                                    }
                                }
                            });
                        if rule.kind != "all" {
                            let hint = match rule.kind.as_str() {
                                "process" => "chrome.exe",
                                "ip" => "1.2.3.0/24",
                                _ => "example.com",
                            };
                            *changed |= ui
                                .add(
                                    egui::TextEdit::singleline(&mut rule.value)
                                        .id(rule_text_id(i))
                                        .hint_text(hint)
                                        .desired_width(150.0),
                                )
                                .changed();
                        }
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if theme::danger_button(ui, "✕") {
                                    remove = Some(i);
                                }
                            },
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.add_space(24.0);
                        egui::ComboBox::from_id_salt(("rule_action", i))
                            .width(132.0)
                            .selected_text(action_label(&rule.action, lang))
                            .show_ui(ui, |ui| {
                                for (value, ru, en) in [
                                    ("proxy", "Через VPN", "Through VPN"),
                                    ("direct", "Напрямую", "Direct"),
                                    ("block", "Блокировать", "Block"),
                                ] {
                                    if ui
                                        .selectable_label(rule.action == value, lang.t(ru, en))
                                        .clicked()
                                    {
                                        rule.action = value.to_owned();
                                        *changed = true;
                                    }
                                }
                            });
                        if rule.action == "proxy" {
                            let current = rule.route.clone().unwrap_or_default();
                            let label = if current.is_empty() {
                                lang.t("Маршрут: по умолчанию", "Route: default")
                            } else {
                                current.as_str()
                            };
                            egui::ComboBox::from_id_salt(("rule_route", i))
                                .width(160.0)
                                .selected_text(label)
                                .show_ui(ui, |ui| {
                                    if ui
                                        .selectable_label(
                                            current.is_empty(),
                                            lang.t("По умолчанию", "Default"),
                                        )
                                        .clicked()
                                    {
                                        rule.route = None;
                                        *changed = true;
                                    }
                                    for name in &routes {
                                        if ui
                                            .selectable_label(
                                                current.as_str() == name.as_str(),
                                                name.as_str(),
                                            )
                                            .clicked()
                                        {
                                            rule.route = Some(name.clone());
                                            *changed = true;
                                        }
                                    }
                                });
                        }
                        ui.with_layout(
                            egui::Layout::right_to_left(egui::Align::Center),
                            |ui| {
                                if i + 1 < count && ui.small_button("↓").clicked() {
                                    move_down = Some(i);
                                }
                                if i > 0 && ui.small_button("↑").clicked() {
                                    move_up = Some(i);
                                }
                            },
                        );
                    });
                }
                if i + 1 < count {
                    ui.separator();
                }
            }
            if self.store.settings.routing_rules.is_empty() {
                theme::hint(
                    ui,
                    lang.t(
                        "Правил пока нет — весь трафик идёт по раздельному маршрутизированию.",
                        "No rules yet — all traffic uses split routing.",
                    ),
                );
            }
            ui.add_space(4.0);
            if theme::tool_button(ui, lang.t("Добавить правило", "Add rule")) {
                self.store
                    .settings
                    .routing_rules
                    .push(crate::store::RoutingRule::default());
                *changed = true;
            }
        });
        if let Some(i) = remove {
            self.store.settings.routing_rules.remove(i);
            *changed = true;
        }
        if let Some(i) = move_up {
            self.store.settings.routing_rules.swap(i, i - 1);
            *changed = true;
        }
        if let Some(i) = move_down {
            self.store.settings.routing_rules.swap(i, i + 1);
            *changed = true;
        }
    }

    fn split_settings(&mut self, ui: &mut egui::Ui, changed: &mut bool) {
        let title = self.tr("Раздельное маршрутизирование", "Split routing");
        let no_profile = self.tr(
            "Активный профиль не использует подписку",
            "The active profile does not use a subscription",
        );
        let split_label = self.tr("Разделять трафик", "Split traffic");
        let inherit = self.tr("Наследовать", "Inherit");
        let direct = self.tr("Напрямую", "Direct");
        let routes = self.store.route_names();
        theme::section_title(ui, title);
        display_split(ui, &self.store, no_profile, changed);

        // Edits are applied to the active subscription profile, the same way
        // Android stores per-profile overrides.
        let active_id = self.store.active.clone();
        if let Some(id) = active_id {
            if let Some(profile) = self.store.profiles.iter_mut().find(|p| p.id == id) {
                theme::card_ui(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(split_label);
                        let mut split = profile.split.unwrap_or(false);
                        if ui.checkbox(&mut split, "").changed() {
                            profile.split = Some(split);
                            *changed = true;
                        }
                    });
                    egui::Grid::new("split_routes")
                        .num_columns(2)
                        .spacing([10.0, 6.0])
                        .show(ui, |ui| {
                            for (label, field) in [
                                ("RU", &mut profile.route_ru),
                                ("Non-RU", &mut profile.route_non_ru),
                                ("Private", &mut profile.route_private),
                            ] {
                                ui.label(label);
                                let mut options: Vec<String> = vec!["direct".to_owned()];
                                options.extend(routes.iter().cloned());
                                if let Some(current) = field.as_deref() {
                                    if !options.iter().any(|option| option == current) {
                                        options.push(current.to_owned());
                                    }
                                }
                                egui::ComboBox::from_id_salt(("split_route", label))
                                    .selected_text(field.as_deref().unwrap_or(inherit))
                                    .width(220.0)
                                    .show_ui(ui, |ui| {
                                        if ui
                                            .selectable_label(field.is_none(), inherit)
                                            .clicked()
                                        {
                                            *field = None;
                                            *changed = true;
                                        }
                                        for option in &options {
                                            let selected =
                                                field.as_deref() == Some(option.as_str());
                                            let text = if option == "direct" {
                                                direct
                                            } else {
                                                option.as_str()
                                            };
                                            if ui.selectable_label(selected, text).clicked() {
                                                *field = Some(option.clone());
                                                *changed = true;
                                            }
                                        }
                                    });
                                ui.end_row();
                            }
                        });
                });

            }
        }
    }

    fn url_settings(&mut self, ui: &mut egui::Ui, changed: &mut bool) {
        theme::section_title(ui, self.tr("URL-серверы", "Entry URLs"));
        let statuses = self
            .shared
            .lock()
            .status
            .as_ref()
            .map(|s| s.urls.clone())
            .unwrap_or_default();
        theme::card_ui(ui, |ui| {
            if statuses.is_empty() {
                theme::hint(
                    ui,
                    self.tr("Статус появится после подключения.", "Status appears after connecting."),
                );
            }
            for url in statuses {
                ui.horizontal(|ui| {
                    let mut enabled = !self
                        .store
                        .settings
                        .disabled_urls
                        .iter()
                        .any(|u| u.trim_end_matches('/') == url.url.trim_end_matches('/'));
                    if ui.checkbox(&mut enabled, "").changed() {
                        let url = url.url.trim_end_matches('/').to_owned();
                        self.store.settings.disabled_urls.retain(|u| u != &url);
                        if !enabled {
                            self.store.settings.disabled_urls.push(url);
                        }
                        *changed = true;
                    }
                    ui.vertical(|ui| {
                        ui.label(egui::RichText::new(short_url(&url.url)).size(12.0));
                        let text = if let Some(secs) = url.quarantined_s {
                            format!("quarantine {secs}s · sessions {}", url.sessions)
                        } else if url.failures > 0 {
                            format!("failures {} · sessions {}", url.failures, url.sessions)
                        } else {
                            format!("ok · sessions {}", url.sessions)
                        };
                        theme::hint(ui, &text);
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(self.tr("Сброс", "Reset")).clicked() {
                            self.backend.clear_url_errors();
                        }
                    });
                });
            }
        });
    }

    fn logs_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(self.tr("Логи", "Logs")).size(16.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(self.tr("Обновить", "Refresh")).clicked() {
                    self.refresh_logs(true);
                }
                if ui.button(self.tr("Копировать", "Copy all")).clicked() {
                    ui.ctx().copy_text(self.logs.clone());
                    self.toast(self.tr("Логи скопированы", "Logs copied"));
                }
                if ui.button(self.tr("Папка", "Folder")).clicked() {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(&self.dir)
                        .spawn();
                }
            });
        });
        ui.add_space(6.0);
        let mut text = self.logs.clone();
        egui::ScrollArea::vertical()
            .stick_to_bottom(true)
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut text)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(30)
                        .interactive(false),
                );
            });
    }
}

fn kind_label(kind: &str, lang: Lang) -> &'static str {
    match kind {
        "process" => lang.t("Процесс", "Process"),
        "ip" => lang.t("IP / CIDR", "IP / CIDR"),
        "all" => lang.t("Всё", "All"),
        _ => lang.t("Домен", "Domain"),
    }
}

fn action_label(action: &str, lang: Lang) -> &'static str {
    match action {
        "direct" => lang.t("Напрямую", "Direct"),
        "block" => lang.t("Блокировать", "Block"),
        _ => lang.t("Через VPN", "Through VPN"),
    }
}

fn display_split(
    ui: &mut egui::Ui,
    store: &Store,
    no_profile: &str,
    _changed: &mut bool,
) {
    theme::card_ui(ui, |ui| {
        let resolved = store
            .active_profile()
            .and_then(|p| store.resolve(Some(p)).ok());
        match resolved {
            Some(resolved) => {
                ui.label(if resolved.split.enabled {
                    store.settings.ui_language
                        .eq_ignore_ascii_case("en")
                        .then_some("Enabled from subscription")
                        .unwrap_or("Включено в подписке")
                } else {
                    store.settings.ui_language
                        .eq_ignore_ascii_case("en")
                        .then_some("Disabled")
                        .unwrap_or("Выключено")
                });
                theme::hint(
                    ui,
                    &format!(
                        "default {} · RU {} · Non-RU {} · Private {}",
                        resolved.split.default,
                        resolved
                            .split
                            .actions
                            .get("ru")
                            .map(|a| if a.direct { "direct" } else { a.route.as_deref().unwrap_or("?") })
                            .unwrap_or("inherit"),
                        resolved
                            .split
                            .actions
                            .get("non_ru")
                            .map(|a| if a.direct { "direct" } else { a.route.as_deref().unwrap_or("?") })
                            .unwrap_or("inherit"),
                        resolved
                            .split
                            .actions
                            .get("private")
                            .map(|a| if a.direct { "direct" } else { a.route.as_deref().unwrap_or("?") })
                            .unwrap_or("inherit"),
                    ),
                );
            }
            None => theme::hint(ui, no_profile),
        }
    });
}

impl App {
    /// Handles Ctrl+C / Ctrl+V for every text field. Windows sends these
    /// combinations as key-release events without a matching press, so the
    /// ordinary egui clipboard events sometimes never arrive.
    fn handle_clipboard_keys(&mut self, ctx: &egui::Context) {
        let (copy, paste) = ctx.input(|i| {
            let ctrl = i.modifiers.ctrl;
            (
                ctrl && (i.key_pressed(egui::Key::C) || i.key_released(egui::Key::C)),
                ctrl && (i.key_pressed(egui::Key::V) || i.key_released(egui::Key::V)),
            )
        });
        if !copy && !paste {
            return;
        }
        let Some(id) = ctx.memory(|m| m.focused()) else {
            return;
        };
        let target = if id == text_id(TEXT_SUB_URL) {
            Some(TextTarget::SubUrl)
        } else if id == text_id(TEXT_SUB_NAME) {
            Some(TextTarget::SubName)
        } else if id == text_id(TEXT_CHECK_URL) {
            Some(TextTarget::CheckUrl)
        } else if id == text_id(TEXT_TUN_ADDRESS) {
            Some(TextTarget::TunAddress)
        } else if id == text_id(TEXT_TUN_NETMASK) {
            Some(TextTarget::TunNetmask)
        } else if id == text_id(TEXT_TUN_DNS) {
            Some(TextTarget::TunDns)
        } else if id == text_id(TEXT_TUN_DNS_UPSTREAM) {
            Some(TextTarget::TunDnsUpstream)
        } else if id == text_id(TEXT_TUN_EXCLUDE) {
            Some(TextTarget::TunExclude)
        } else if let Some(index) = (0..self.store.settings.routing_rules.len())
            .find(|index| id == rule_text_id(*index))
        {
            Some(TextTarget::RuleValue(index))
        } else {
            None
        };
        let Some(target) = target else {
            return;
        };
        let range = egui::widgets::text_edit::TextEditState::load(ctx, id)
            .and_then(|state| state.cursor.char_range());

        match target {
            TextTarget::SubUrl => Self::clipboard_on(ctx, &mut self.new_sub, copy, paste, range),
            TextTarget::SubName => {
                Self::clipboard_on(ctx, &mut self.new_sub_name, copy, paste, range)
            }
            TextTarget::CheckUrl => {
                Self::clipboard_on(ctx, &mut self.store.settings.check_url, copy, paste, range)
            }
            TextTarget::TunAddress => Self::clipboard_on(
                ctx,
                &mut self.store.settings.tun_address,
                copy,
                paste,
                range,
            ),
            TextTarget::TunNetmask => Self::clipboard_on(
                ctx,
                &mut self.store.settings.tun_netmask,
                copy,
                paste,
                range,
            ),
            TextTarget::TunDns => {
                Self::clipboard_on(ctx, &mut self.store.settings.tun_dns, copy, paste, range)
            }
            TextTarget::TunDnsUpstream => Self::clipboard_on(
                ctx,
                &mut self.store.settings.tun_dns_upstream,
                copy,
                paste,
                range,
            ),
            TextTarget::TunExclude => {
                if copy {
                    let joined = self.store.settings.tun_exclude.join(", ");
                    let selected = range
                        .map(|r| slice_chars(&joined, r))
                        .unwrap_or(joined);
                    ctx.copy_text(selected);
                }
                if paste {
                    if let Some(text) = platform::clipboard_text() {
                        self.store.settings.tun_exclude = text
                            .split([',', ' ', ';'])
                            .map(str::trim)
                            .filter(|s| !s.is_empty())
                            .map(str::to_owned)
                            .collect();
                    }
                }
            }
            TextTarget::RuleValue(index) => {
                if let Some(rule) = self.store.settings.routing_rules.get_mut(index) {
                    Self::clipboard_on(ctx, &mut rule.value, copy, paste, range);
                }
            }
        }
    }

    fn clipboard_on(
        ctx: &egui::Context,
        text: &mut String,
        copy: bool,
        paste: bool,
        range: Option<egui::text_selection::CCursorRange>,
    ) {
        if copy {
            let selected = range
                .map(|r| slice_chars(text, r))
                .unwrap_or_else(|| text.clone());
            ctx.copy_text(selected);
        }
        if paste {
            if let Some(clipped) = platform::clipboard_text() {
                if let Some(range) = range {
                    text.replace_range(byte_range(text, range), &clipped);
                } else {
                    *text = clipped;
                }
            }
        }
    }
}

impl eframe::App for App {
    /// Runs even while the window is hidden, so tray menus and background
    /// session state keep working in the tray.
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Copying the tunnel snapshot is the only thing that makes the latency
        // change, so it must not run on every mouse-driven repaint. One tick
        // per second is enough; while connecting, poll faster so the state
        // switch is not delayed.
        let busy = {
            let shared = self.shared.lock();
            shared.busy || shared.test_busy
        };
        let interval = if busy {
            Duration::from_millis(200)
        } else {
            Duration::from_secs(1)
        };
        if busy != self.was_busy || self.refresh_at.elapsed() >= interval {
            self.backend.refresh();
            self.refresh_at = Instant::now();
        }
        self.was_busy = busy;
        self.apply_store_revision();

        let running = self.shared.lock().running;
        if running != self.last_shared_running {
            self.last_shared_running = running;
            self.tray = Tray::new(self.lang, running);
        }
        self.ensure_tray(ctx);
        self.update_tray(ctx);
        self.handle_close(ctx);

        if let Some(notice) = self.backend.take_notice() {
            match notice.as_str() {
                "connected" => self.toast(self.tr("Подключено", "Connected")),
                "disconnected" => self.toast(self.tr("Отключено", "Disconnected")),
                "subscription_added" => {
                    self.toast(self.tr("Подписка добавлена", "Subscription added"))
                }
                other if other.starts_with("refreshed:") => {
                    self.toast(self.tr("Подписки обновлены", "Subscriptions refreshed"))
                }
                _ => self.toast(notice),
            }
        }

        if self.reconnect_after_disconnect {
            let shared = self.shared.lock();
            if !shared.busy && !shared.running {
                drop(shared);
                self.reconnect_after_disconnect = false;
                self.connect();
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let ctx = &ctx;
        self.handle_clipboard_keys(ctx);
        self.refresh_logs(false);

        self.header(ui);
        egui::CentralPanel::default()
            .frame(
                egui::Frame::NONE
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| match self.page {
                        Page::Home | Page::Settings => {
                            let width = CONTENT_WIDTH.min(ui.available_width());
                            let side = ((ui.available_width() - width) * 0.5).max(0.0);
                            ui.horizontal(|ui| {
                                ui.add_space(side);
                                ui.vertical(|ui| {
                                    ui.set_width(width);
                                    match self.page {
                                        Page::Home => self.home(ui),
                                        _ => self.settings(ui),
                                    }
                                });
                            });
                        }
                        Page::Logs => self.logs_page(ui),
                    });
            });

        let update = self.shared.lock().update_available.clone();
        if let Some(version) = update {
            if !self.update_dismissed {
                let mut dismissed = false;
                let mut check_updates = self.store.settings.ui_check_updates;
                egui::Window::new(self.tr("Доступно обновление", "Update available"))
                    .collapsible(false)
                    .resizable(false)
                    .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
                    .show(ctx, |ui| {
                        ui.label(format!("v{} → v{}", crate::VERSION, version));
                        ui.checkbox(
                            &mut check_updates,
                            self.tr("Проверять обновления", "Check for updates"),
                        );
                        ui.horizontal(|ui| {
                            if ui.button(self.tr("Скачать", "Download")).clicked() {
                                ctx.open_url(egui::OpenUrl::new_tab(
                                    "https://github.com/victor-osipov-dev/short-polling-vpn/releases/latest",
                                ));
                            }
                            if ui.button("OK").clicked() {
                                dismissed = true;
                            }
                        });
                    });
                self.store.settings.ui_check_updates = check_updates;
                if dismissed || !check_updates {
                    self.update_dismissed = true;
                    if !check_updates {
                        self.save();
                    }
                }
            }
        }

        if let Some((text, until)) = &self.toast {
            if Instant::now() < *until {
                egui::Area::new(egui::Id::unique("toast"))
                    .anchor(egui::Align2::CENTER_BOTTOM, egui::vec2(0.0, -12.0))
                    .show(ctx, |ui| {
                        egui::Frame::NONE
                            .fill(theme::CARD_HOVER)
                            .stroke(egui::Stroke::new(1.0, theme::BORDER))
                            .corner_radius(10)
                            .inner_margin(egui::Margin::symmetric(14, 8))
                            .show(ui, |ui| {
                                ui.label(egui::RichText::new(text).size(12.0));
                            });
                    });
            } else {
                self.toast = None;
            }
        }

        let busy = self.shared.lock().busy || self.shared.lock().test_busy;
        ctx.request_repaint_after(if busy {
            Duration::from_millis(120)
        } else {
            Duration::from_millis(500)
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.backend.disconnect_blocking();
    }
}

/// Small flag emoji for the active profile name, when we recognise the country.
fn country_code(name: &str) -> &'static str {
    let n = name.to_lowercase();
    if n.contains("финлянд") {
        "FI"
    } else if n.contains("герман") {
        "DE"
    } else if n.contains("япон") {
        "JP"
    } else if n.contains("польш") {
        "PL"
    } else if n.contains("нидерланд") || n.contains("голланд") {
        "NL"
    } else if n.contains("росси") {
        "RU"
    } else {
        "VPN"
    }
}

fn human_bytes(value: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = value as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{} {}", value as u64, UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

fn short_url(url: &str) -> String {
    let url = url.trim_end_matches('/');
    if url.len() <= 54 {
        url.to_owned()
    } else {
        format!("{}…{}", &url[..30], &url[url.len() - 20..])
    }
}

fn icon_rgba(size: u32) -> Vec<u8> {
    const ICON_PNG: &[u8] = include_bytes!("../../assets/icon.png");
    if let Ok(image) = image::load_from_memory(ICON_PNG) {
        let rgba = image.to_rgba8();
        if rgba.width() == size && rgba.height() == size {
            return rgba.into_raw();
        }
        return image::imageops::resize(
            &rgba,
            size,
            size,
            image::imageops::FilterType::Lanczos3,
        )
        .into_raw();
    }
    // Fallback so the window still opens if the asset is unreadable.
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for pixel in rgba.chunks_exact_mut(4) {
        pixel.copy_from_slice(&[77, 163, 255, 255]);
    }
    rgba
}

#[allow(dead_code)]
fn _path(_: &Path) {}
