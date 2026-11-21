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

pub fn run(dir: PathBuf, minimized: bool) -> Result<()> {
    let minimized = minimized
        || Store::load(&dir)
            .map(|store| store.settings.ui_start_minimized)
            .unwrap_or(false);
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([430.0, 700.0])
            .with_min_inner_size([390.0, 560.0])
            .with_title("SPVPN")
            .with_icon(egui::IconData {
                rgba: icon_rgba(64),
                width: 64,
                height: 64,
            })
            .with_visible(!minimized),
        ..Default::default()
    };
    eframe::run_native(
        "SPVPN",
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
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, dir: PathBuf, minimized: bool) -> Result<Self> {
        std::fs::create_dir_all(&dir)?;
        theme::apply(&cc.egui_ctx);
        let store = Store::load(&dir)?;
        let lang = Lang::from_code(&store.settings.ui_language);
        let backend = Backend::new(&dir)?;
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
                self.tr("SPVPN — отключение…", "SPVPN — disconnecting…")
            } else if shared.running {
                self.tr("SPVPN — подключено", "SPVPN — connected")
            } else if shared.busy {
                self.tr("SPVPN — подключение…", "SPVPN — connecting…")
            } else {
                "SPVPN"
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
                    .fill(theme::BG)
                    .inner_margin(egui::Margin::symmetric(16, 10)),
            )
            .show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(egui::RichText::new("SPVPN").size(18.0).strong());
                    ui.add_space(8.0);
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui
                            .selectable_label(self.lang == Lang::En, "EN")
                            .clicked()
                        {
                            self.lang = Lang::En;
                            self.store.settings.ui_language = "en".into();
                            self.save();
                            self.tray = Tray::new(self.lang, self.shared.lock().running);
                        }
                        if ui
                            .selectable_label(self.lang == Lang::Ru, "RU")
                            .clicked()
                        {
                            self.lang = Lang::Ru;
                            self.store.settings.ui_language = "ru".into();
                            self.save();
                            self.tray = Tray::new(self.lang, self.shared.lock().running);
                        }
                        ui.add_space(8.0);
                        self.nav_button(ui, Page::Logs, self.tr("Логи", "Logs"));
                        self.nav_button(ui, Page::Settings, self.tr("Настройки", "Settings"));
                        self.nav_button(ui, Page::Home, self.tr("VPN", "VPN"));
                    });
                });
            });
    }

    fn nav_button(&mut self, ui: &mut egui::Ui, page: Page, text: &str) {
        if ui.selectable_label(self.page == page, text).clicked() {
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
                    theme::pill(
                        ui,
                        if disconnecting {
                            self.tr("ОТКЛЮЧЕНИЕ", "DISCONNECTING")
                        } else if running {
                            self.tr("ПОДКЛЮЧЕНО", "CONNECTED")
                        } else if busy {
                            self.tr("ПОДКЛЮЧЕНИЕ", "CONNECTING")
                        } else {
                            self.tr("ОТКЛЮЧЕНО", "DISCONNECTED")
                        },
                        color,
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mode = self.active_profile_mode();
                        if ui
                            .selectable_label(mode == "proxy", self.tr("Прокси", "Proxy"))
                            .clicked()
                        {
                            self.set_active_mode("proxy");
                        }
                        if ui
                            .selectable_label(mode == "vpn", "VPN")
                            .clicked()
                        {
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
                ui.label(egui::RichText::new(profile).size(22.0).strong());
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
                        .size(19.0)
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
            ui.horizontal(|ui| {
                self.stat(ui, self.tr("Сессии", "Sessions"), &status.active_sessions.to_string());
                ui.separator();
                self.stat(
                    ui,
                    self.tr("Задержка", "Latency"),
                    &status
                        .last_poll_age_ms
                        .map(|ms| format!("{ms} ms"))
                        .unwrap_or_else(|| "—".into()),
                );
                ui.separator();
                self.stat(
                    ui,
                    self.tr("Трафик", "Traffic"),
                    &format!(
                        "↑{}  ↓{}",
                        human_bytes(status.tx_bytes),
                        human_bytes(status.rx_bytes)
                    ),
                );
                ui.separator();
                self.stat(
                    ui,
                    self.tr("Время", "Uptime"),
                    &format_duration(status.uptime_s),
                );
            });
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
        ui.vertical(|ui| {
            ui.label(egui::RichText::new(value).size(14.0).strong());
            theme::hint(ui, label);
        });
    }

    fn subscriptions(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(egui::RichText::new(self.tr("Профили", "Profiles")).size(16.0).strong());
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui
                    .button(self.tr("+ Подписка", "+ Subscription"))
                    .clicked()
                {
                    self.add_open = !self.add_open;
                }
                if ui.button(self.tr("Обновить", "Refresh")).clicked() {
                    self.backend.refresh_subscriptions();
                    self.toast(self.tr("Обновление подписок…", "Refreshing subscriptions…"));
                }
                if ui.button(self.tr("Тест всех", "Test all")).clicked() {
                    self.test_profiles(true, None);
                    ui.ctx().request_repaint();
                }
            });
        });
        ui.add_space(4.0);

        if self.add_open {
            theme::card_ui(ui, |ui| {
                ui.label(egui::RichText::new(self.tr("Новая подписка", "New subscription")).strong());
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_sub)
                        .hint_text("https://example/subscription.json")
                        .desired_width(f32::INFINITY),
                );
                let name_hint = self.tr("Название (необязательно)", "Name (optional)");
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_sub_name)
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
                    }
                    if ui.button(self.tr("Отмена", "Cancel")).clicked() {
                        self.add_open = false;
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
                    if ui
                        .small_button(self.tr("Удалить", "Remove"))
                        .clicked()
                    {
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
        egui::Frame::NONE
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
                        *select = Some(id.to_owned());
                    }
                    ui.label(egui::RichText::new(name).strong());
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.small_button(self.tr("Тест", "Test")).clicked() {
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
                        if !result.ok {
                            theme::hint(ui, &result.error);
                        } else if !result.exit_ip.is_empty() {
                            theme::hint(ui, &format!("exit {}", result.exit_ip));
                        }
                    }
                }
            });
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
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Маска", "Netmask"));
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_netmask)
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label("DNS");
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_dns)
                                .desired_width(150.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label("MTU");
                    changed |= ui
                        .add(egui::DragValue::new(&mut self.store.settings.tun_mtu).range(576..=9000))
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("DNS-сервер", "DNS upstream"));
                    changed |= ui
                        .add(
                            egui::TextEdit::singleline(&mut self.store.settings.tun_dns_upstream)
                                .desired_width(180.0),
                        )
                        .changed();
                    ui.end_row();
                    ui.label(self.tr("Исключения", "Exclusions"));
                    let mut text = self.store.settings.tun_exclude.join(", ");
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut text)
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
        });

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
                        if ui.small_button(self.tr("Удалить", "Remove")).clicked() {
                            self.store.remove_subscription(&id);
                            changed = true;
                        }
                    });
                });
            }
            ui.add_space(4.0);
            if ui
                .button(self.tr("Обновить все", "Refresh all"))
                .clicked()
            {
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
