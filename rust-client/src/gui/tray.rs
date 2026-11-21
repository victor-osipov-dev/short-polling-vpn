use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use super::i18n::Lang;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TrayAction {
    Show,
    Connect,
    Disconnect,
    Quit,
}

pub struct Tray {
    _icon: TrayIcon,
}

impl Tray {
    pub fn new(lang: Lang, running: bool) -> Option<Self> {
        let menu = Menu::new();
        let show = MenuItem::with_id("show", lang.t("Открыть", "Open"), true, None);
        let connect = MenuItem::with_id(
            "connect",
            lang.t("Подключить", "Connect"),
            !running,
            None,
        );
        let disconnect = MenuItem::with_id(
            "disconnect",
            lang.t("Отключить", "Disconnect"),
            running,
            None,
        );
        let quit = MenuItem::with_id("quit", lang.t("Выход", "Quit"), true, None);
        let separator = PredefinedMenuItem::separator();
        let separator2 = PredefinedMenuItem::separator();
        let _ = menu.append_items(&[
            &show,
            &separator,
            &connect,
            &disconnect,
            &separator2,
            &quit,
        ]);
        let icon = TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("SPVPN")
            .with_icon(app_icon())
            .with_menu_on_left_click(false)
            .build()
            .ok()?;
        Some(Self { _icon: icon })
    }

    pub fn set_tooltip(&self, text: &str) {
        let _ = self._icon.set_tooltip(Some(text));
    }

    pub fn poll(&self) -> Vec<TrayAction> {
        let mut actions = Vec::new();
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            match event.id.0.as_str() {
                "show" => actions.push(TrayAction::Show),
                "connect" => actions.push(TrayAction::Connect),
                "disconnect" => actions.push(TrayAction::Disconnect),
                "quit" => actions.push(TrayAction::Quit),
                _ => {}
            }
        }
        while let Ok(event) = TrayIconEvent::receiver().try_recv() {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                actions.push(TrayAction::Show);
            }
        }
        actions
    }
}

pub fn app_icon() -> Icon {
    let size = 32u32;
    Icon::from_rgba(super::icon_rgba(size), size, size).expect("valid icon")
}
