"""
Desktop VPN Client — GUI (tkinter, тёмная тема).

Аналог Android-приложения: профили, подписки, split-routing, проверка
подключения и живой статус URL.

Запуск:
    python vpn_gui.py --config config.yaml

Если `profiles.json` ещё нет, профиль создаётся из config.yaml (миграция).
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
from typing import Optional

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image, ImageDraw

# ── Импорт движка из общих модулей ──
from tunnel import ClientTunnel
from socks5_server import handle_socks_client
from desktop_client import handle_http_client, set_system_proxy_windows
from desktop_config import DesktopConfig, default_profile_config
from connection_test import test_profile


# ══════════════════════════════════════════════════════════════════════
#  Локализация (как в Android L.t)
# ══════════════════════════════════════════════════════════════════════

class L:
    ru = True

    @staticmethod
    def t(en: str, ru: str) -> str:
        return ru if L.ru else en


def tr(en: str, ru: str) -> str:
    return L.t(en, ru)


# ══════════════════════════════════════════════════════════════════════
#  Цветовая палитра — Soft Dark
# ══════════════════════════════════════════════════════════════════════

BG_MAIN     = "#1e1e2e"
BG_PANEL    = "#252536"
BG_LOG      = "#1a1a28"
BG_INPUT    = "#2a2a3c"
FG_TEXT     = "#cdd6f4"
FG_LABEL    = "#7f849c"
FG_GREEN    = "#a6e3a1"
FG_RED      = "#f38ba8"
FG_BLUE     = "#89b4fa"
FG_AMBER    = "#f9e2af"
BORDER      = "#45475a"
BTN_ON      = "#40a02b"
BTN_OFF     = "#d20f39"
BTN_HOVER_ON = "#369020"
BTN_HOVER_OFF = "#b80d32"
BTN_ACCENT  = "#2563eb"
BTN_ACCENT_HOVER = "#1d4ed8"


# ══════════════════════════════════════════════════════════════════════
#  Логгер → tkinter виджет
# ══════════════════════════════════════════════════════════════════════

class TkLogHandler(logging.Handler):
    """Потокобезопасный хендлер: пишет логи в scrolledtext через queue."""

    def __init__(self, log_widget: scrolledtext.ScrolledText):
        super().__init__()
        self.widget = log_widget
        self._queue = []
        self._pending = False

    def emit(self, record):
        try:
            msg = self.format(record)
            self._queue.append(msg)
            if not self._pending:
                self._pending = True
                self.widget.after(50, self._flush)
        except Exception:
            pass

    def _flush(self):
        self._pending = False
        while self._queue:
            msg = self._queue.pop(0)
            self.widget.configure(state="normal")
            self.widget.insert(tk.END, msg + "\n")
            self.widget.see(tk.END)
            self.widget.configure(state="disabled")
            lines = int(self.widget.index("end-1c").split(".")[0])
            if lines > 2000:
                self.widget.configure(state="normal")
                self.widget.delete("1.0", f"{lines - 1500}.0")
                self.widget.configure(state="disabled")


# ══════════════════════════════════════════════════════════════════════
#  Watchdog handler для отслеживания изменений config.yaml
# ══════════════════════════════════════════════════════════════════════

class ConfigFileHandler(FileSystemEventHandler):
    """Срабатывает при изменении config.yaml — планирует callback в main thread."""

    def __init__(self, config_path: str, root, callback):
        super().__init__()
        self._config_path = os.path.abspath(config_path)
        self._root = root
        self._callback = callback
        self._last_event = 0

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self._config_path:
            now = time.time()
            if now - self._last_event > 1.0:
                self._last_event = now
                self._root.after(0, self._callback)


# ══════════════════════════════════════════════════════════════════════
#  Хелперы UI
# ══════════════════════════════════════════════════════════════════════

class ScrollFrame(tk.Frame):
    """Прокручиваемый контейнер: кладите виджеты в `.inner`.

    Колесо мыши обрабатывается только пока курсор над этим контейнером,
    поэтому несколько ScrollFrame на экране не мешают друг другу.
    """

    def __init__(self, parent, bg=BG_MAIN, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0)
        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.canvas.bind("<Enter>", self._bind_wheel)
        self.canvas.bind("<Leave>", self._unbind_wheel)

    def _on_inner(self, _e=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, event=None):
        self.canvas.itemconfigure(self._window, width=self.canvas.winfo_width())

    def _bind_wheel(self, _e=None):
        self.canvas.bind_all("<MouseWheel>", self._on_wheel)

    def _unbind_wheel(self, _e=None):
        self.canvas.unbind_all("<MouseWheel>")

    def _on_wheel(self, event):
        self.canvas.yview_scroll(int(-event.delta / 120), "units")


def _chip(parent, text, selected, command, bg=BG_PANEL):
    btn = tk.Button(
        parent, text=text, command=command, font=("Segoe UI", 9),
        bg=(BTN_ACCENT if selected else BG_INPUT),
        fg="white", relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2",
        activebackground=(BTN_ACCENT_HOVER if selected else BORDER),
        activeforeground="white",
    )
    return btn


# ══════════════════════════════════════════════════════════════════════
#  Главное окно
# ══════════════════════════════════════════════════════════════════════

class VpnGui:
    def __init__(self, cfg: DesktopConfig, config_path: str = "config.yaml"):
        self.cfg = cfg                      # DesktopConfig (профили/подписки)
        self.config_path = config_path
        self._config_mtime = os.path.getmtime(config_path) if os.path.exists(config_path) else 0
        self.running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._tunnel: ClientTunnel | None = None
        self._observer: Observer | None = None
        self._test_results: dict[str, dict] = {}
        self._testing: set[str] = set()
        self._last_url_status: dict[str, dict] = {}

        # Язык
        L.ru = (self.cfg.get_pref("language", "ru") == "ru")

        self._reload_display_config()

        # ── Tk root ──
        self.root = tk.Tk()
        self.root.title("Short Polling VPN")
        self.root.geometry("560x780")
        self.root.minsize(460, 640)
        self.root.configure(bg=BG_MAIN)
        self.root.resizable(True, True)

        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self._settings_win: Optional[tk.Toplevel] = None
        self._build_ui()
        self._start_config_watcher()
        self._create_tray_icon()
        self._refresh_profiles()

    # ── Загрузка активного профиля ──

    def _reload_display_config(self):
        """Перечитывает активный профиль и параметры для отображения."""
        self.cfg.ensure_profiles()
        profile = self.cfg.get_active_profile()
        self.active_profile = profile
        engine = self.cfg.engine_config(profile)
        client_cfg = engine.get("client", {})
        socks_cfg = client_cfg.get("socks5", {})
        self.socks_host = socks_cfg.get("bind_host", "127.0.0.1")
        self.socks_port = socks_cfg.get("bind_port", 8888)
        self.http_port = socks_cfg.get("http_port", 8889)
        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        self.server_urls = [u.rstrip("/") for u in urls if u]
        self.engine_cfg = engine

    # ══════════════════════════════════════════════════════════════════
    #  Построение интерфейса
    # ══════════════════════════════════════════════════════════════════

    def _build_ui(self):
        root = self.root
        self.FONT   = ("Segoe UI", 10)
        self.FONT_B = ("Segoe UI", 10, "bold")
        self.FONT_S = ("Segoe UI", 9)
        self.FONT_L = ("Segoe UI", 14, "bold")

        # ═══ Заголовок ═══
        header = tk.Frame(root, bg=BG_PANEL, height=56)
        header.pack(fill=tk.X, padx=10, pady=(10, 5))
        header.pack_propagate(False)

        tk.Label(header, text="Short Polling VPN",
                 font=self.FONT_L, bg=BG_PANEL, fg=FG_TEXT).pack(side=tk.LEFT, padx=14)

        self.settings_btn = tk.Button(
            header, text="\u2699 " + tr("Settings", "Настройки"), font=self.FONT_S,
            bg=BG_PANEL, fg=FG_LABEL, relief=tk.FLAT, bd=0, cursor="hand2",
            activebackground=BG_PANEL, activeforeground=FG_TEXT,
            command=self._open_settings,
        )
        self.settings_btn.pack(side=tk.RIGHT, padx=10)

        self.status_frame = tk.Frame(header, bg=BG_PANEL)
        self.status_frame.pack(side=tk.RIGHT, padx=14)

        self.status_dot = tk.Canvas(self.status_frame, width=12, height=12,
                                     bg=BG_PANEL, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 6))
        self._dot_id = self.status_dot.create_oval(1, 1, 11, 11, fill=FG_RED, outline="")

        self.status_label = tk.Label(self.status_frame, text="OFFLINE",
                                      font=self.FONT_B, bg=BG_PANEL, fg=FG_RED)
        self.status_label.pack(side=tk.LEFT)

        # ═══ Прокручиваемая область ═══
        scroll_outer = tk.Frame(root, bg=BG_MAIN)
        scroll_outer.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self._scroll = ScrollFrame(scroll_outer, bg=BG_MAIN)
        self._scroll.pack(fill=tk.BOTH, expand=True)
        self.body = self._scroll.inner

        # ── Кнопка Connect ──
        btn_frame = tk.Frame(self.body, bg=BG_MAIN)
        btn_frame.pack(fill=tk.X, pady=(6, 4))

        self.start_btn = tk.Button(
            btn_frame, text="Connect", font=self.FONT_L,
            bg=BTN_ON, fg="white", activebackground=BTN_HOVER_ON,
            activeforeground="white", relief=tk.FLAT, cursor="hand2",
            bd=0, command=self._on_toggle
        )
        self.start_btn.pack(fill=tk.X, ipady=8)
        self.start_btn.bind("<Enter>", self._on_btn_hover_enter)
        self.start_btn.bind("<Leave>", self._on_btn_hover_leave)

        # ── Активный профиль ──
        self.active_label = tk.Label(self.body, text="", font=("Segoe UI", 13, "bold"),
                                     bg=BG_MAIN, fg=FG_TEXT)
        self.active_label.pack(pady=(8, 2))

        # ── Статус-бар ──
        self.info_bar = tk.Frame(self.body, bg=BG_PANEL, height=30)
        self.info_bar.pack(fill=tk.X, pady=(2, 6))
        self.info_bar.pack_propagate(False)
        self.info_label = tk.Label(self.info_bar, text=tr("Press Connect to start", "Нажмите Connect для подключения"),
                                    font=self.FONT_S, bg=BG_PANEL, fg=FG_LABEL)
        self.info_label.pack(side=tk.LEFT, padx=14, pady=4)
        self.proxy_indicator = tk.Label(self.info_bar, text="", font=self.FONT_S, bg=BG_PANEL)
        self.proxy_indicator.pack(side=tk.RIGHT, padx=14, pady=4)

        # ── Карточка подписки ──
        self.sub_card = tk.Frame(self.body, bg=BG_PANEL, highlightbackground=BORDER,
                                 highlightthickness=1)
        self.sub_card.pack(fill=tk.X, pady=6)

        # ── Список профилей ──
        self.profiles_frame = tk.Frame(self.body, bg=BG_MAIN)
        self.profiles_frame.pack(fill=tk.X, pady=6)

        # ── Лог ──
        log_frame = tk.Frame(self.body, bg=BG_MAIN)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(8, 10))
        tk.Label(log_frame, text="Log", font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL, anchor=tk.W).pack(anchor=tk.W, padx=4, pady=(0, 4))

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, font=("Consolas", 9),
            bg=BG_LOG, fg=FG_TEXT, insertbackground=FG_TEXT,
            selectbackground=FG_BLUE, selectforeground="white",
            relief=tk.FLAT, state="disabled", height=12, borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)
        for tag, color in (("INFO", FG_TEXT), ("WARNING", FG_AMBER),
                            ("ERROR", FG_RED), ("DEBUG", FG_LABEL)):
            self.log_text.tag_config(tag, foreground=color)

    def _display_host(self):
        if self.socks_host in ("0.0.0.0", ""):
            return "127.0.0.1"
        return self.socks_host

    # ══════════════════════════════════════════════════════════════════
    #  Профили и подписки (главный экран)
    # ══════════════════════════════════════════════════════════════════

    def _refresh_profiles(self):
        """Перестраивает карточку подписки, список профилей и заголовок."""
        self._reload_display_config()
        profile = self.active_profile
        if profile:
            mode = "VPN" if profile["mode"] == "vpn" else "Proxy"
            self.active_label.configure(
                text=f"{profile['name']}  ·  {mode}")
        else:
            self.active_label.configure(text=tr("No profile", "Нет профиля"))

        self._build_subscription_card()
        self._build_profiles_list()
        self._update_server_display()

    def _build_subscription_card(self):
        for w in self.sub_card.winfo_children():
            w.destroy()

        profile = self.active_profile
        cfg = profile["config"] if profile else default_profile_config()
        sub = cfg.get("subscription", {})
        name = sub.get("name") or cfg["user"].get("uuid", "")[:8] or tr("No subscription", "Нет подписки")

        tk.Label(self.sub_card, text=tr("Subscription", "Подписка"), font=self.FONT_B,
                 bg=BG_PANEL, fg=FG_TEXT).pack(anchor=tk.W, padx=14, pady=(12, 2))
        tk.Label(self.sub_card, text=name, font=self.FONT, bg=BG_PANEL,
                 fg=FG_BLUE).pack(anchor=tk.W, padx=14)
        if sub.get("url"):
            tk.Label(self.sub_card, text=sub["url"], font=self.FONT_S, bg=BG_PANEL,
                     fg=FG_LABEL, anchor=tk.W, wraplength=480,
                     justify=tk.LEFT).pack(anchor=tk.W, padx=14, pady=(2, 0))

        row = tk.Frame(self.sub_card, bg=BG_PANEL)
        row.pack(fill=tk.X, padx=14, pady=10)
        tk.Button(row, text=tr("Add subscription", "Добавить подписку"), font=self.FONT_B,
                  bg=BTN_ACCENT, fg="white", relief=tk.FLAT, bd=0, padx=14, pady=6,
                  cursor="hand2", activebackground=BTN_ACCENT_HOVER, activeforeground="white",
                  command=self._add_subscription_dialog).pack(side=tk.LEFT)
        tk.Button(row, text=tr("From clipboard", "Из буфера"), font=self.FONT_S,
                  bg=BG_INPUT, fg=FG_TEXT, relief=tk.FLAT, bd=0, padx=10, pady=6,
                  cursor="hand2", activebackground=BORDER, activeforeground="white",
                  command=self._import_from_clipboard).pack(side=tk.LEFT, padx=6)
        tk.Button(row, text=tr("From file", "Из файла"), font=self.FONT_S,
                  bg=BG_INPUT, fg=FG_TEXT, relief=tk.FLAT, bd=0, padx=10, pady=6,
                  cursor="hand2", activebackground=BORDER, activeforeground="white",
                  command=self._import_from_file).pack(side=tk.LEFT)

        if sub.get("url"):
            tk.Button(self.sub_card, text=tr("Refresh subscription", "Обновить подписку"),
                      font=self.FONT_S, bg=BG_PANEL, fg=FG_BLUE, relief=tk.FLAT, bd=0,
                      cursor="hand2", activebackground=BG_PANEL, activeforeground=FG_TEXT,
                      command=lambda: self._import_subscription_text(sub["url"], select=False)
                      ).pack(anchor=tk.W, padx=14, pady=(0, 12))

    def _build_profiles_list(self):
        for w in self.profiles_frame.winfo_children():
            w.destroy()

        header = tk.Frame(self.profiles_frame, bg=BG_MAIN)
        header.pack(fill=tk.X)
        tk.Label(header, text=tr("Profiles", "Профили"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_TEXT).pack(side=tk.LEFT, padx=4)
        tk.Button(header, text=tr("Manage", "Управление"), font=self.FONT_S, bg=BG_MAIN,
                  fg=FG_BLUE, relief=tk.FLAT, bd=0, cursor="hand2",
                  activebackground=BG_MAIN, activeforeground=FG_TEXT,
                  command=lambda: self._open_settings(tab="general")).pack(side=tk.RIGHT)

        groups = self.cfg.group_profiles()
        if not groups:
            tk.Label(self.profiles_frame, text=tr("No profiles yet. Add a subscription above.",
                                                  "Профилей нет. Добавьте подписку выше."),
                     font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL).pack(anchor=tk.W, padx=6, pady=6)
            return

        active_id = self.cfg.get_active_id()

        for sub_url, profiles in groups:
            first = profiles[0]
            title = (first["config"]["subscription"].get("name")
                     or tr("Local profiles", "Локальные профили"))
            gh = tk.Frame(self.profiles_frame, bg=BG_MAIN)
            gh.pack(fill=tk.X, pady=(8, 2))
            tk.Label(gh, text=title, font=self.FONT_B, bg=BG_MAIN, fg=FG_TEXT,
                     anchor=tk.W).pack(side=tk.LEFT, padx=4)
            tk.Button(gh, text=tr("Test all", "Тест всех"), font=self.FONT_S, bg=BG_MAIN,
                      fg=FG_BLUE, relief=tk.FLAT, bd=0, cursor="hand2",
                      activebackground=BG_MAIN, activeforeground=FG_TEXT,
                      command=lambda ps=profiles: self._test_profiles(ps)).pack(side=tk.RIGHT)
            if sub_url:
                tk.Button(gh, text="✕", font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL,
                          relief=tk.FLAT, bd=0, cursor="hand2",
                          activebackground=BG_MAIN, activeforeground=FG_RED,
                          command=lambda u=sub_url, n=title: self._delete_subscription(u, n)
                          ).pack(side=tk.RIGHT, padx=6)

            for p in profiles:
                self._build_profile_card(p, p["id"] == active_id)

    def _build_profile_card(self, profile: dict, active: bool):
        card = tk.Frame(self.profiles_frame, bg=(BG_PANEL if not active else "#1b2a4a"),
                        highlightbackground=(FG_BLUE if active else BORDER),
                        highlightthickness=1)
        card.pack(fill=tk.X, pady=3)

        inner = tk.Frame(card, bg=card["bg"])
        inner.pack(fill=tk.X, padx=10, pady=8)

        left = tk.Frame(inner, bg=card["bg"])
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)

        name_row = tk.Frame(left, bg=card["bg"])
        name_row.pack(anchor=tk.W)
        if active:
            tk.Label(name_row, text="\u25cf", font=("Segoe UI", 8), bg=card["bg"],
                     fg=FG_GREEN).pack(side=tk.LEFT, padx=(0, 6))
        tk.Label(name_row, text=profile["name"], font=self.FONT_B, bg=card["bg"],
                 fg=FG_TEXT).pack(side=tk.LEFT)

        mode = "VPN" if profile["mode"] == "vpn" else "Proxy"
        tk.Label(left, text=mode, font=self.FONT_S, bg=card["bg"],
                 fg=FG_LABEL).pack(anchor=tk.W, padx=(2 if not active else 16, 0))

        result = self._test_results.get(profile["id"])
        line, color = self._test_line(profile["id"], result)
        if line:
            tk.Label(left, text=line, font=("Segoe UI", 8), bg=card["bg"],
                     fg=color, anchor=tk.W, justify=tk.LEFT,
                     wraplength=380).pack(anchor=tk.W, padx=(2 if not active else 16, 0))

        tk.Button(inner, text=tr("Test", "Тест"), font=self.FONT_S, bg=BG_INPUT, fg=FG_TEXT,
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2",
                  activebackground=BORDER, activeforeground="white",
                  command=lambda p=profile: self._test_profiles([p])).pack(side=tk.RIGHT, padx=6)
        tk.Button(inner, text=(tr("Active", "Активен") if active else tr("Select", "Выбрать")),
                  font=self.FONT_S, bg=(BTN_ACCENT if not active else BG_INPUT),
                  fg="white", relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2",
                  activebackground=(BTN_ACCENT_HOVER if not active else BORDER),
                  activeforeground="white",
                  command=lambda p=profile: self._select_profile(p["id"])).pack(side=tk.RIGHT)

    def _test_line(self, profile_id: str, result):
        if profile_id in self._testing:
            return tr("Checking connection…", "Проверка подключения…"), FG_BLUE
        if not result:
            return "", FG_LABEL
        if result.get("ok"):
            parts = []
            latency = result.get("latency_ms") or 0
            parts.append(f"{latency} ms" if latency else "OK")
            if result.get("exit_ip"):
                parts.append("exit " + result["exit_ip"])
            if result.get("route"):
                parts.append(result["route"])
            return "  ·  ".join(parts), FG_GREEN
        return tr("Failed: ", "Ошибка: ") + str(result.get("error") or "no response"), FG_RED

    def _select_profile(self, profile_id: str):
        self.cfg.select_profile(profile_id)
        self._refresh_profiles()
        if self.running:
            self._log(tr("Profile changed. Reconnect to apply.",
                         "Профиль изменён. Переподключитесь для применения."), "INFO")

    def _delete_subscription(self, url: str, name: str):
        if not messagebox.askyesno(
                tr("Delete subscription", "Удалить подписку"),
                tr(f"Delete \"{name}\" and all its profiles? Other subscriptions stay.",
                   f"Удалить \"{name}\" и все её профили? Другие подписки останутся.")):
            return
        self.cfg.delete_subscription(url)
        self._refresh_profiles()

    # ── Проверка подключения ──

    def _test_profiles(self, profiles: list[dict]):
        if not profiles:
            return
        for p in profiles:
            self._testing.add(p["id"])
            self._test_results.pop(p["id"], None)
        self._refresh_profiles()
        threading.Thread(target=self._run_tests, args=(list(profiles),), daemon=True).start()

    def _run_tests(self, profiles: list[dict]):
        for p in profiles:
            try:
                engine = self.cfg.engine_config(p)
                # Проверяем ровно то, что выбрал пользователь: локальные
                # действия профиля важнее действий из подписки.
                result = test_profile(engine, timeout=15.0)
            except Exception as exc:
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            self._test_results[p["id"]] = result
            self._testing.discard(p["id"])
            self.root.after(0, self._refresh_profiles)

    # ── Импорт подписки ──

    def _add_subscription_dialog(self):
        win = tk.Toplevel(self.root)
        win.title(tr("Add subscription", "Добавить подписку"))
        win.configure(bg=BG_MAIN)
        win.geometry("560x240")
        win.transient(self.root)

        tk.Label(win, text=tr("Subscription URL or JSON", "URL подписки или JSON"),
                 font=self.FONT_B, bg=BG_MAIN, fg=FG_TEXT).pack(anchor=tk.W, padx=14, pady=(14, 4))
        text = tk.Text(win, height=6, font=("Consolas", 9), bg=BG_INPUT, fg=FG_TEXT,
                       insertbackground=FG_TEXT, relief=tk.FLAT, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=14, pady=4)
        try:
            clip = self.root.clipboard_get()
            if clip and len(clip) < 5000:
                text.insert("1.0", clip)
        except Exception:
            pass

        def apply():
            raw = text.get("1.0", tk.END).strip()
            win.destroy()
            self._import_subscription_text(raw)

        row = tk.Frame(win, bg=BG_MAIN)
        row.pack(fill=tk.X, padx=14, pady=(0, 12))
        tk.Button(row, text=tr("Add", "Добавить"), font=self.FONT_B, bg=BTN_ACCENT, fg="white",
                  relief=tk.FLAT, bd=0, padx=16, pady=6, cursor="hand2",
                  activebackground=BTN_ACCENT_HOVER, activeforeground="white",
                  command=apply).pack(side=tk.RIGHT)
        tk.Button(row, text=tr("Cancel", "Отмена"), font=self.FONT, bg=BG_INPUT, fg=FG_TEXT,
                  relief=tk.FLAT, bd=0, padx=16, pady=6, cursor="hand2",
                  activebackground=BORDER, activeforeground="white",
                  command=win.destroy).pack(side=tk.RIGHT, padx=8)

    def _import_from_clipboard(self):
        try:
            raw = self.root.clipboard_get()
        except Exception:
            messagebox.showwarning(tr("Clipboard", "Буфер обмена"),
                                   tr("Clipboard is empty", "Буфер обмена пуст"))
            return
        self._import_subscription_text(raw)

    def _import_from_file(self):
        path = filedialog.askopenfilename(
            title=tr("Select subscription JSON", "Выберите JSON подписки"),
            filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        if path:
            self._import_subscription_text(path)

    def _import_subscription_text(self, raw: str, select: bool = True):
        raw = (raw or "").strip()
        if not raw:
            return
        self._log(tr("Loading subscription…", "Загрузка подписки…"), "INFO")
        threading.Thread(target=self._import_worker, args=(raw, select), daemon=True).start()

    def _import_worker(self, raw: str, select: bool):
        try:
            from subscription import load_subscription
            if raw.startswith("{"):
                sub = json.loads(raw)
                source_url = ""
            else:
                sub = load_subscription(raw)
                source_url = raw
            profile = self.cfg.import_subscription(sub, source_url, select=select)
            if profile:
                self.root.after(0, lambda: (
                    self._log(tr(f"OK: {profile['name']}", f"OK: {profile['name']}"), "INFO"),
                    self._refresh_profiles(),
                ))
        except Exception as exc:
            self.root.after(0, lambda e=exc: self._log(
                tr(f"Subscription error: {e}", f"Ошибка подписки: {e}"), "ERROR"))

    # ══════════════════════════════════════════════════════════════════
    #  Настройки (отдельное окно)
    # ══════════════════════════════════════════════════════════════════

    def _open_settings(self, tab: str = "general"):
        if self._settings_win and self._settings_win.winfo_exists():
            self._settings_win.lift()
            self._settings_win.focus_force()
            self._select_settings_tab(tab)
            return

        win = tk.Toplevel(self.root)
        win.title(tr("Settings", "Настройки"))
        win.configure(bg=BG_MAIN)
        win.geometry("620x720")
        win.transient(self.root)
        win.protocol("WM_DELETE_WINDOW", self._close_settings)
        self._settings_win = win

        notebook = ttk.Notebook(win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self._notebook = notebook

        self.tab_general = tk.Frame(notebook, bg=BG_MAIN)
        self.tab_connection = tk.Frame(notebook, bg=BG_MAIN)
        self.tab_logs = tk.Frame(notebook, bg=BG_MAIN)
        notebook.add(self.tab_general, text=tr("General", "Общее"))
        notebook.add(self.tab_connection, text=tr("Connection", "Подключение"))
        notebook.add(self.tab_logs, text=tr("Logs", "Логи"))

        self._build_general_tab()
        self._build_connection_tab()
        self._build_logs_tab()
        self._select_settings_tab(tab)

    def _select_settings_tab(self, tab: str):
        idx = {"general": 0, "connection": 1, "logs": 2}.get(tab, 0)
        try:
            self._notebook.select(idx)
        except Exception:
            pass

    def _close_settings(self):
        win = self._settings_win
        self._settings_win = None
        try:
            if win and win.winfo_exists():
                win.destroy()
        except Exception:
            pass
        # Виджет лога из окна настроек уничтожен — больше не пишем в него.
        self.settings_log = None
        # Закрывая настройки, подхватываем возможные правки профилей.
        self._refresh_profiles()

    def _build_general_tab(self):
        for w in self.tab_general.winfo_children():
            w.destroy()

        # Язык
        lang = tk.Frame(self.tab_general, bg=BG_MAIN)
        lang.pack(fill=tk.X, padx=14, pady=(14, 6))
        tk.Label(lang, text=tr("Language:", "Язык:"), font=self.FONT, bg=BG_MAIN,
                 fg=FG_LABEL).pack(side=tk.LEFT)
        cur = self.cfg.get_pref("language", "ru")
        _chip(lang, "English", cur == "en", lambda: self._set_language("en"), bg=BG_MAIN).pack(side=tk.LEFT, padx=6)
        _chip(lang, "Русский", cur == "ru", lambda: self._set_language("ru"), bg=BG_MAIN).pack(side=tk.LEFT)

        tk.Frame(self.tab_general, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)

        tk.Label(self.tab_general, text=tr("Profiles", "Профили"), font=self.FONT_B,
                 bg=BG_MAIN, fg=FG_TEXT).pack(anchor=tk.W, padx=14, pady=(0, 4))
        tk.Label(self.tab_general,
                 text=tr("Each profile stores mode, connection settings and routing. Changes apply on reconnect.",
                         "Каждый профиль хранит режим, настройки подключения и маршрутизацию. Изменения применяются при переподключении."),
                 font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL, wraplength=560,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=14)

        # список профилей
        list_scroll = ScrollFrame(self.tab_general, bg=BG_MAIN)
        list_scroll.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        list_inner = list_scroll.inner
        self._general_list = list_inner

        active_id = self.cfg.get_active_id()
        for p in self.cfg.load_profiles():
            is_active = p["id"] == active_id
            card = tk.Frame(list_inner, bg=(BG_PANEL if not is_active else "#1b2a4a"),
                            highlightbackground=(FG_BLUE if is_active else BORDER), highlightthickness=1)
            card.pack(fill=tk.X, pady=2)
            row = tk.Frame(card, bg=card["bg"])
            row.pack(fill=tk.X, padx=10, pady=6)
            tk.Label(row, text=p["name"], font=self.FONT_B, bg=card["bg"], fg=FG_TEXT).pack(side=tk.LEFT)
            tk.Label(row, text=("VPN" if p["mode"] == "vpn" else "Proxy"), font=self.FONT_S,
                     bg=card["bg"], fg=FG_LABEL).pack(side=tk.LEFT, padx=8)
            tk.Button(row, text="✕", font=self.FONT_S, bg=card["bg"], fg=FG_LABEL, relief=tk.FLAT,
                      bd=0, cursor="hand2", activebackground=card["bg"], activeforeground=FG_RED,
                      command=lambda pr=p: self._delete_profile(pr)).pack(side=tk.RIGHT)
            if is_active:
                tk.Label(row, text=tr("ACTIVE", "АКТИВЕН"), font=("Segoe UI", 8),
                         bg=card["bg"], fg=FG_BLUE).pack(side=tk.RIGHT, padx=6)
            else:
                tk.Button(row, text=tr("Set Active", "Активировать"), font=self.FONT_S,
                          bg=BG_INPUT, fg="white", relief=tk.FLAT, bd=0, padx=8, pady=3,
                          cursor="hand2", activebackground=BORDER, activeforeground="white",
                          command=lambda pr=p: self._select_profile_settings(pr)).pack(side=tk.RIGHT)

        # кнопки управления
        manage = tk.Frame(self.tab_general, bg=BG_MAIN)
        manage.pack(fill=tk.X, padx=14, pady=(4, 12))
        for label_en, label_ru, cmd in (
            ("New", "Новый", self._new_profile),
            ("Rename", "Переименовать", self._rename_profile),
            ("Duplicate", "Дублировать", self._duplicate_profile),
        ):
            tk.Button(manage, text=tr(label_en, label_ru), font=self.FONT_S, bg=BG_INPUT,
                      fg="white", relief=tk.FLAT, bd=0, padx=10, pady=5, cursor="hand2",
                      activebackground=BORDER, activeforeground="white",
                      command=cmd).pack(side=tk.LEFT, padx=4)

    def _delete_profile(self, profile: dict):
        if not messagebox.askyesno(tr("Delete profile", "Удалить профиль"),
                                   tr(f"Delete \"{profile['name']}\"? This cannot be undone.",
                                      f"Удалить \"{profile['name']}\"? Это нельзя отменить.")):
            return
        self.cfg.delete_profile(profile["id"])
        self._build_general_tab()
        self._refresh_profiles()

    def _select_profile_settings(self, profile: dict):
        self.cfg.select_profile(profile["id"])
        self._build_general_tab()
        self._build_connection_tab()
        self._refresh_profiles()

    def _new_profile(self):
        name = simpledialog.askstring(tr("New profile", "Новый профиль"),
                                      tr("Profile name", "Имя профиля"), parent=self.root)
        if not name:
            return
        import uuid as _uuid
        profile = {"id": str(_uuid.uuid4()), "name": name, "mode": "proxy",
                   "config": default_profile_config()}
        self.cfg.add_profile(profile)
        self.cfg.select_profile(profile["id"])
        self._build_general_tab()
        self._build_connection_tab()
        self._refresh_profiles()

    def _rename_profile(self):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        name = simpledialog.askstring(tr("Rename profile", "Переименовать профиль"),
                                      tr("Profile name", "Имя профиля"),
                                      initialvalue=profile["name"], parent=self.root)
        if not name:
            return
        profile["name"] = name
        self.cfg.update_profile(profile)
        self._build_general_tab()
        self._refresh_profiles()

    def _duplicate_profile(self):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        name = simpledialog.askstring(tr("Duplicate profile", "Дублировать профиль"),
                                      tr("Profile name", "Имя профиля"),
                                      initialvalue=profile["name"] + " copy", parent=self.root)
        if not name:
            return
        import copy as _copy
        import uuid as _uuid
        new = {"id": str(_uuid.uuid4()), "name": name, "mode": profile["mode"],
               "config": _copy.deepcopy(profile["config"])}
        self.cfg.add_profile(new)
        self.cfg.select_profile(new["id"])
        self._build_general_tab()
        self._build_connection_tab()
        self._refresh_profiles()

    def _set_language(self, lang: str):
        self.cfg.set_pref("language", lang)
        L.ru = (lang == "ru")
        messagebox.showinfo(tr("Language", "Язык"),
                            tr("Restart the app to apply the language.",
                               "Перезапустите приложение, чтобы применить язык."))

    # ── Вкладка Connection ──

    def _build_connection_tab(self):
        for w in self.tab_connection.winfo_children():
            w.destroy()

        conn_scroll = ScrollFrame(self.tab_connection, bg=BG_MAIN)
        conn_scroll.pack(fill=tk.BOTH, expand=True)
        inner = conn_scroll.inner
        self._conn_inner = inner

        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()
        client = cfg["client"]

        tk.Label(inner, text=tr("Subscription", "Подписка"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(12, 4))

        sub_row = tk.Frame(inner, bg=BG_MAIN)
        sub_row.pack(fill=tk.X, padx=14)
        self.sub_url_var = tk.StringVar(value=cfg["subscription"].get("url", ""))
        entry = tk.Entry(sub_row, textvariable=self.sub_url_var, font=("Consolas", 9),
                         bg=BG_INPUT, fg=FG_TEXT, insertbackground=FG_TEXT, relief=tk.FLAT)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        tk.Button(sub_row, text=tr("Load", "Загрузить"), font=self.FONT_S, bg=BTN_ACCENT,
                  fg="white", relief=tk.FLAT, bd=0, padx=12, pady=5, cursor="hand2",
                  activebackground=BTN_ACCENT_HOVER, activeforeground="white",
                  command=lambda: self._import_subscription_text(self.sub_url_var.get())).pack(side=tk.LEFT, padx=6)

        if cfg["user"].get("uuid"):
            tk.Label(inner, text=f"{tr('User', 'Пользователь')}: {cfg['user']['uuid']}",
                     font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(4, 0))

        # ── Режим профиля ──
        tk.Label(inner, text=tr("Mode", "Режим"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(12, 4))
        mode_row = tk.Frame(inner, bg=BG_MAIN)
        mode_row.pack(fill=tk.X, padx=14)
        _chip(mode_row, tr("Proxy (SOCKS5)", "Прокси (SOCKS5)"), profile and profile["mode"] == "proxy",
              lambda: self._set_mode("proxy"), bg=BG_MAIN).pack(side=tk.LEFT)
        _chip(mode_row, "VPN", profile and profile["mode"] == "vpn",
              lambda: self._set_mode("vpn"), bg=BG_MAIN).pack(side=tk.LEFT, padx=6)
        if profile and profile["mode"] == "vpn":
            tk.Label(inner,
                     text=tr("VPN mode uses system-wide capture on Windows via the system proxy setting.",
                             "VPN-режим на Windows использует системный прокси (перехват всего трафика приложениями)."),
                     font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL, wraplength=560,
                     justify=tk.LEFT).pack(anchor=tk.W, padx=14, pady=(4, 0))

        tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)

        # ── Split routing ──
        tk.Label(inner, text=tr("Routing", "Маршрутизация"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(0, 4))
        routing = cfg["routing"]
        rrow = tk.Frame(inner, bg=BG_MAIN)
        rrow.pack(fill=tk.X, padx=14)
        tk.Label(rrow, text=tr("Split routing:", "Раздельная маршрутизация"), font=self.FONT,
                 bg=BG_MAIN, fg=FG_TEXT).pack(side=tk.LEFT)
        self.routing_var = tk.BooleanVar(value=bool(routing.get("enabled")))
        tk.Checkbutton(rrow, variable=self.routing_var, bg=BG_MAIN, activebackground=BG_MAIN,
                       selectcolor=BG_INPUT, command=self._on_routing_toggle).pack(side=tk.LEFT, padx=8)

        route_names = [r for r in (cfg.get("routing_options") or "").split("|") if r]
        options = route_names + ["direct"]
        if self.routing_var.get():
            if not route_names:
                tk.Label(inner, text=tr("Load a subscription to get route names.",
                                        "Загрузите подписку, чтобы получить названия маршрутов."),
                         font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL).pack(anchor=tk.W, padx=14)
            self._route_selector(inner, tr("RU", "RU"), "ru", routing.get("ru", ""), options)
            self._route_selector(inner, tr("non-RU", "не-RU"), "non_ru",
                                 routing.get("non_ru", ""), options)
            self._route_selector(inner, tr("Private / LAN", "Локальная сеть"), "private",
                                 routing.get("private", "direct"), options)

        tk.Frame(inner, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)

        # ── URL серверов ──
        tk.Label(inner, text=tr("Server URLs:", "Серверные URL:"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(0, 4))
        self._server_url_vars = []
        for i, url in enumerate(client.get("server_urls") or []):
            row = tk.Frame(inner, bg=BG_MAIN)
            row.pack(fill=tk.X, padx=14, pady=2)
            enabled_var = tk.BooleanVar(value=url.rstrip("/") not in {u.rstrip("/") for u in client.get("disabled_urls", [])})
            tk.Checkbutton(row, variable=enabled_var, bg=BG_MAIN, activebackground=BG_MAIN,
                           selectcolor=BG_INPUT,
                           command=lambda u=url, v=enabled_var: self._toggle_url(u, v.get())).pack(side=tk.LEFT)
            var = tk.StringVar(value=url)
            self._server_url_vars.append((var, enabled_var))
            entry = tk.Entry(row, textvariable=var, font=("Consolas", 9), bg=BG_INPUT,
                             fg=FG_TEXT, insertbackground=FG_TEXT, relief=tk.FLAT)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4, padx=6)
            entry.bind("<FocusOut>", lambda _e, idx=i, v=var: self._save_server_url(idx, v.get()))
            entry.bind("<Return>", lambda _e, idx=i, v=var: self._save_server_url(idx, v.get()))
            tk.Button(row, text="✕", font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL, relief=tk.FLAT,
                      bd=0, cursor="hand2", activebackground=BG_MAIN, activeforeground=FG_RED,
                      command=lambda idx=i: self._remove_url(idx)).pack(side=tk.LEFT)

        tk.Button(inner, text=tr("+ Add URL", "+ Добавить URL"), font=self.FONT_S, bg=BG_INPUT,
                  fg="white", relief=tk.FLAT, bd=0, padx=10, pady=5, cursor="hand2",
                  activebackground=BORDER, activeforeground="white",
                  command=self._add_url).pack(anchor=tk.W, padx=14, pady=6)

        # ── Статус URL ──
        self.url_status_frame = tk.Frame(inner, bg=BG_PANEL, highlightbackground=BORDER,
                                         highlightthickness=1)
        self.url_status_frame.pack(fill=tk.X, padx=14, pady=6)
        self._build_url_status()
        # ── Параметры ──
        self._build_advanced_fields(inner, client)

    def _build_advanced_fields(self, parent, client: dict):
        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()

        def field(label, value, key, cast=lambda v: v):
            row = tk.Frame(parent, bg=BG_MAIN)
            row.pack(fill=tk.X, padx=14, pady=2)
            tk.Label(row, text=label, font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL,
                     width=20, anchor=tk.W).pack(side=tk.LEFT)
            var = tk.StringVar(value=str(value))

            def save(*_):
                try:
                    self._set_client_value(key, cast(var.get()))
                except Exception:
                    pass

            entry = tk.Entry(row, textvariable=var, font=("Consolas", 9), bg=BG_INPUT,
                             fg=FG_TEXT, insertbackground=FG_TEXT, relief=tk.FLAT)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=3)
            entry.bind("<FocusOut>", save)
            entry.bind("<Return>", save)
            return var

        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)
        tk.Label(parent, text=tr("Advanced", "Дополнительно"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(0, 4))
        field(tr("Poll interval (ms)", "Интервал опроса (мс)"), client.get("poll_interval_ms", 200),
              "poll_interval_ms", int)
        field(tr("Max chunk", "Макс. чанк"), client.get("max_chunk_bytes", 65536),
              "max_chunk_bytes", int)
        field(tr("Poll path", "Путь опроса"), client.get("poll_path", "/poll"), "poll_path", str)
        field(tr("Host header", "Host-заголовок"), client.get("host_header", ""), "host_header", str)
        field(tr("SOCKS port", "Порт SOCKS"), client["socks5"].get("bind_port", 8888),
              "socks_port", int)
        field(tr("HTTP port", "Порт HTTP"), client["socks5"].get("http_port", 8889),
              "http_port", int)
        field(tr("Quarantine (s)", "Карантин (с)"), client.get("url_cooldown_seconds", 60),
              "url_cooldown_seconds", int)
        field(tr("Fail limit", "Лимит ошибок"), client.get("url_fail_limit", 3),
              "url_fail_limit", int)

        pad_row = tk.Frame(parent, bg=BG_MAIN)
        pad_row.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(pad_row, text=tr("Pad poll sizes", "Маскировать размеры poll"), font=self.FONT,
                 bg=BG_MAIN, fg=FG_TEXT).pack(side=tk.LEFT)
        pad_var = tk.BooleanVar(value=bool(client.get("pad_polls", True)))
        tk.Checkbutton(pad_row, variable=pad_var, bg=BG_MAIN, activebackground=BG_MAIN,
                       selectcolor=BG_INPUT,
                       command=lambda: self._set_client_value("pad_polls", pad_var.get())).pack(side=tk.LEFT, padx=8)

        method_row = tk.Frame(parent, bg=BG_MAIN)
        method_row.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(method_row, text=tr("Method:", "Метод:"), font=self.FONT, bg=BG_MAIN,
                 fg=FG_TEXT).pack(side=tk.LEFT)
        for m in ("GET", "POST"):
            _chip(method_row, m, client.get("poll_method", "POST").upper() == m,
                  lambda mm=m: self._set_client_value("poll_method", mm), bg=BG_MAIN).pack(side=tk.LEFT, padx=4)

        data_row = tk.Frame(parent, bg=BG_MAIN)
        data_row.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(data_row, text=tr("Data in:", "Данные в:"), font=self.FONT, bg=BG_MAIN,
                 fg=FG_TEXT).pack(side=tk.LEFT)
        for d in ("body", "header"):
            _chip(data_row, d, client.get("poll_data_in", "body") == d,
                  lambda dd=d: self._set_client_value("poll_data_in", dd), bg=BG_MAIN).pack(side=tk.LEFT, padx=4)

        tls_row = tk.Frame(parent, bg=BG_MAIN)
        tls_row.pack(fill=tk.X, padx=14, pady=4)
        tk.Label(tls_row, text=tr("Verify TLS:", "Проверять TLS:"), font=self.FONT, bg=BG_MAIN,
                 fg=FG_TEXT).pack(side=tk.LEFT)
        tls_var = tk.BooleanVar(value=bool(client.get("verify_tls", True)))
        tk.Checkbutton(tls_row, variable=tls_var, bg=BG_MAIN, activebackground=BG_MAIN,
                       selectcolor=BG_INPUT,
                       command=lambda: self._set_client_value("verify_tls", tls_var.get())).pack(side=tk.LEFT, padx=8)

        # Advanced JSON
        tk.Frame(parent, bg=BORDER, height=1).pack(fill=tk.X, padx=14, pady=10)
        tk.Label(parent, text=tr("Advanced config (JSON)", "Продвинутый конфиг (JSON)"),
                 font=self.FONT_B, bg=BG_MAIN, fg=FG_LABEL).pack(anchor=tk.W, padx=14)
        tk.Label(parent, text=tr("Server block is ignored; only client and security sections matter.",
                                 "Блок server игнорируется; важны только client и security."),
                 font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL, wraplength=560,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=14, pady=(0, 4))
        self.raw_editor = tk.Text(parent, height=12, font=("Consolas", 9), bg=BG_LOG,
                                  fg=FG_TEXT, insertbackground=FG_TEXT, relief=tk.FLAT, wrap=tk.NONE)
        self.raw_editor.pack(fill=tk.X, padx=14, pady=4)
        self.raw_editor.insert("1.0", json.dumps(cfg, ensure_ascii=False, indent=2))
        tk.Button(parent, text=tr("Save config", "Сохранить конфиг"), font=self.FONT_S,
                  bg=BTN_ACCENT, fg="white", relief=tk.FLAT, bd=0, padx=12, pady=5,
                  cursor="hand2", activebackground=BTN_ACCENT_HOVER, activeforeground="white",
                  command=self._save_raw_config).pack(anchor=tk.W, padx=14, pady=(4, 14))

    # ── Настройки профиля ──

    def _current_profile(self) -> Optional[dict]:
        return self.cfg.get_active_profile()

    def _mutate_profile(self, fn):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        new_config = fn(profile["config"])
        if new_config is None:
            return
        profile["config"] = new_config
        self.cfg.update_profile(profile)
        self._refresh_profiles()

    def _set_mode(self, mode: str):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        profile["mode"] = mode
        self.cfg.update_profile(profile)
        self._build_connection_tab()
        self._refresh_profiles()

    def _set_client_value(self, key: str, value):
        def fn(cfg):
            client = cfg["client"]
            if key == "socks_port":
                client["socks5"]["bind_port"] = int(value)
            elif key == "http_port":
                client["socks5"]["http_port"] = int(value)
            else:
                client[key] = value
            return cfg
        self._mutate_profile(fn)

    def _on_routing_toggle(self):
        enabled = self.routing_var.get()

        def fn(cfg):
            cfg["routing"]["enabled"] = enabled
            return cfg

        self._mutate_profile(fn)
        self._build_connection_tab()

    def _route_selector(self, parent, label: str, key: str, value: str, options: list[str]):
        box = tk.Frame(parent, bg=BG_MAIN)
        box.pack(fill=tk.X, padx=14, pady=3)
        tk.Label(box, text=label + ":", font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL,
                 width=14, anchor=tk.W).pack(side=tk.LEFT)
        chips = tk.Frame(box, bg=BG_MAIN)
        chips.pack(side=tk.LEFT, fill=tk.X, expand=True)
        for opt in options:
            text = "Direct" if opt == "direct" else opt
            _chip(chips, text, value == opt,
                  lambda o=opt: self._set_route(key, o), bg=BG_MAIN).pack(side=tk.LEFT, padx=2)

    def _set_route(self, key: str, route: str):
        def fn(cfg):
            cfg["routing"][key] = route
            return cfg

        self._mutate_profile(fn)
        self._build_connection_tab()

    def _toggle_url(self, url: str, enabled: bool):
        normalized = url.rstrip("/")

        def fn(cfg):
            disabled = list(cfg["client"].get("disabled_urls") or [])
            disabled = [u for u in disabled if u.rstrip("/") != normalized]
            if not enabled:
                disabled.append(normalized)
            cfg["client"]["disabled_urls"] = disabled
            return cfg

        self._mutate_profile(fn)
        # Если туннель запущен — применяем на лету.
        if self._tunnel and self._loop:
            disabled = self.cfg.get_active_profile()["config"]["client"]["disabled_urls"]
            self._loop.call_soon_threadsafe(self._tunnel.set_disabled_urls, disabled)

    def _add_url(self):
        def fn(cfg):
            urls = list(cfg["client"].get("server_urls") or [])
            urls.append("")
            cfg["client"]["server_urls"] = urls
            return cfg

        self._mutate_profile(fn)
        self._build_connection_tab()

    def _save_server_url(self, idx: int, value: str):
        value = (value or "").strip()

        def fn(cfg):
            urls = list(cfg["client"].get("server_urls") or [])
            if not (0 <= idx < len(urls)):
                return cfg
            urls[idx] = value
            clean = [u for u in (u.rstrip("/") for u in urls) if u]
            cfg["client"]["server_urls"] = clean
            cfg["client"]["server_url"] = clean[0] if clean else ""
            return cfg

        self._mutate_profile(fn)

    def _remove_url(self, idx: int):
        def fn(cfg):
            urls = list(cfg["client"].get("server_urls") or [])
            if 0 <= idx < len(urls):
                removed = urls.pop(idx).rstrip("/")
                cfg["client"]["server_urls"] = urls
                cfg["client"]["server_url"] = urls[0] if urls else ""
                cfg["client"]["disabled_urls"] = [
                    u for u in (cfg["client"].get("disabled_urls") or [])
                    if u.rstrip("/") != removed]
            return cfg

        self._mutate_profile(fn)
        self._build_connection_tab()

    def _save_raw_config(self):
        raw = self.raw_editor.get("1.0", tk.END).strip()
        try:
            parsed = json.loads(raw)
        except Exception as exc:
            messagebox.showerror(tr("Invalid JSON", "Некорректный JSON"), str(exc))
            return
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        profile["config"] = parsed
        self.cfg.update_profile(profile)
        messagebox.showinfo(tr("Saved", "Сохранено"), tr("Config saved", "Конфиг сохранён"))
        self._build_connection_tab()
        self._refresh_profiles()

    # ── Статус URL ──

    def _build_url_status(self):
        for w in self.url_status_frame.winfo_children():
            w.destroy()

        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()
        urls = [u for u in (cfg["client"].get("server_urls") or []) if u]

        head = tk.Frame(self.url_status_frame, bg=BG_PANEL)
        head.pack(fill=tk.X, padx=12, pady=(10, 4))
        tk.Label(head, text=tr("URL status", "Статус URL"), font=self.FONT_B, bg=BG_PANEL,
                 fg=FG_TEXT).pack(side=tk.LEFT)
        tk.Button(head, text=tr("Reset errors", "Сбросить ошибки"), font=self.FONT_S, bg=BG_PANEL,
                  fg=FG_BLUE, relief=tk.FLAT, bd=0, cursor="hand2",
                  activebackground=BG_PANEL, activeforeground=FG_TEXT,
                  command=self._reset_url_errors).pack(side=tk.RIGHT)

        if not urls:
            tk.Label(self.url_status_frame, text=tr("No server URLs configured",
                                                    "URL серверов не настроены"),
                     font=self.FONT_S, bg=BG_PANEL, fg=FG_LABEL).pack(anchor=tk.W, padx=12, pady=4)

        for url in urls:
            runtime = self._last_url_status.get(url.rstrip("/"))
            disabled = url.rstrip("/") in {u.rstrip("/") for u in cfg["client"].get("disabled_urls", [])}
            if self.running and runtime is not None:
                disabled = not runtime.get("enabled", True)
            if disabled:
                label, color = tr("Disabled", "Отключён"), FG_LABEL
            elif runtime and runtime.get("quarantined"):
                label = tr("Quarantine", "Карантин") + f" · {runtime.get('cooldown_remaining', 0)}s"
                color = FG_AMBER
            elif runtime and runtime.get("errors", 0) > 0:
                label = tr("Active", "Активен") + f" · {runtime['errors']} " + tr("error(s)", "ошиб.")
                color = FG_RED
            else:
                label, color = tr("Active", "Активен"), FG_GREEN

            row = tk.Frame(self.url_status_frame, bg=BG_PANEL)
            row.pack(fill=tk.X, padx=12, pady=1)
            tk.Label(row, text="\u25cf", font=("Segoe UI", 7), bg=BG_PANEL,
                     fg=color).pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(row, text=url, font=("Consolas", 8), bg=BG_PANEL, fg=FG_TEXT,
                     anchor=tk.W).pack(side=tk.LEFT)
            tk.Label(row, text=label, font=("Segoe UI", 8), bg=BG_PANEL,
                     fg=color).pack(side=tk.RIGHT)

        tk.Label(self.url_status_frame,
                 text=(tr("URL changes and quarantine time apply after reconnect.",
                          "Изменения URL и карантин применяются после переподключения.")
                       if self.running else
                       tr("Connect to see live quarantine state.",
                          "Подключитесь, чтобы увидеть живой статус карантина.")),
                 font=("Segoe UI", 8), bg=BG_PANEL, fg=FG_LABEL, wraplength=520,
                 justify=tk.LEFT).pack(anchor=tk.W, padx=12, pady=(4, 10))

    def _reset_url_errors(self):
        if self._tunnel and self._loop:
            self._loop.call_soon_threadsafe(self._tunnel.reset_url_status)
            self._log(tr("URL error counters reset", "Счётчики ошибок URL сброшены"), "INFO")

    def _build_logs_tab(self):
        for w in self.tab_logs.winfo_children():
            w.destroy()
        tk.Label(self.tab_logs, text=tr("Service log", "Сервисный лог"), font=self.FONT_B,
                 bg=BG_MAIN, fg=FG_LABEL).pack(anchor=tk.W, padx=10, pady=(10, 4))

        self.settings_log = scrolledtext.ScrolledText(
            self.tab_logs, wrap=tk.WORD, font=("Consolas", 9), bg=BG_LOG, fg=FG_TEXT,
            insertbackground=FG_TEXT, relief=tk.FLAT, state="disabled")
        self.settings_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        for tag, color in (("INFO", FG_TEXT), ("WARNING", FG_AMBER),
                            ("ERROR", FG_RED), ("DEBUG", FG_LABEL)):
            self.settings_log.tag_config(tag, foreground=color)

        # Копируем текущее содержимое главного лога.
        try:
            content = self.log_text.get("1.0", tk.END)
            self.settings_log.configure(state="normal")
            self.settings_log.insert("1.0", content)
            self.settings_log.configure(state="disabled")
        except Exception:
            pass

        row = tk.Frame(self.tab_logs, bg=BG_MAIN)
        row.pack(fill=tk.X, padx=10, pady=(0, 10))
        tk.Button(row, text=tr("Copy all", "Копировать всё"), font=self.FONT_S, bg=BG_INPUT,
                  fg="white", relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2",
                  activebackground=BORDER, activeforeground="white",
                  command=self._copy_logs).pack(side=tk.LEFT)
        tk.Button(row, text=tr("Clear", "Очистить"), font=self.FONT_S, bg=BG_INPUT, fg="white",
                  relief=tk.FLAT, bd=0, padx=10, pady=4, cursor="hand2",
                  activebackground=BORDER, activeforeground="white",
                  command=self._clear_logs).pack(side=tk.LEFT, padx=6)

    def _copy_logs(self):
        try:
            text = self.settings_log.get("1.0", tk.END)
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
        except Exception:
            pass

    def _clear_logs(self):
        for widget in (self.log_text, getattr(self, "settings_log", None)):
            if widget is None:
                continue
            widget.configure(state="normal")
            widget.delete("1.0", tk.END)
            widget.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════
    #  System Tray
    # ══════════════════════════════════════════════════════════════════

    def _create_tray_icon(self):
        icon_image = self._create_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("Show", self._tray_show, default=True),
            pystray.MenuItem("Quit", self._tray_quit),
        )
        self._tray = pystray.Icon("VPN", icon_image, "Short Polling VPN", menu)
        self._tray_thread = threading.Thread(target=self._tray.run, daemon=True)
        self._tray_thread.start()

    def _create_tray_image(self):
        img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([1, 1, 14, 14], fill="#252536", outline="#a6e3a1")
        draw.rectangle([4, 4, 11, 11], fill="#a6e3a1")
        return img

    def _tray_show(self, icon=None, item=None):
        self.root.after(0, self._show_window)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_quit(self, icon=None, item=None):
        self.root.after(0, self._quit_app)

    def _on_hide(self):
        self.root.withdraw()

    # ── Hover-эффекты ──

    def _on_btn_hover_enter(self, e):
        self.start_btn.configure(bg=BTN_HOVER_OFF if self.running else BTN_HOVER_ON)

    def _on_btn_hover_leave(self, e):
        self.start_btn.configure(bg=BTN_OFF if self.running else BTN_ON)

    # ══════════════════════════════════════════════════════════════════
    #  Запуск / Остановка
    # ══════════════════════════════════════════════════════════════════

    def _on_toggle(self):
        if self.running:
            self._stop()
        else:
            self._start()

    def _start(self):
        self._reload_display_config()
        if not self.active_profile:
            messagebox.showwarning(tr("No profile", "Нет профиля"),
                                   tr("Add a subscription or create a profile first.",
                                      "Сначала добавьте подписку или создайте профиль."))
            return

        self.running = True
        self.start_btn.configure(text="Disconnect", bg=BTN_OFF, fg="white")
        self._update_status(True)
        self.info_label.configure(text=tr("Connecting...", "Подключение..."))
        self._log("VPN starting...", "INFO")

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        self.root.after(1500, self._check_started)
        self._schedule_proxy_guard()
        self._schedule_url_status()
        self._start_config_watcher()

    def _schedule_proxy_guard(self):
        if not self.running:
            return
        if (self.active_profile and self.active_profile["mode"] == "vpn"
                and sys.platform == "win32"
                and self.socks_host in ("0.0.0.0", "127.0.0.1", "localhost")):
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    needs_fix = (not enabled or "127.0.0.1" not in server
                                 or str(self.http_port) not in server)
                if needs_fix:
                    self._log("Proxy was overwritten — re-setting", "WARNING")
                    set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, True)
            except Exception:
                pass
        self.root.after(3000, self._schedule_proxy_guard)

    def _schedule_url_status(self):
        if not self.running:
            return
        tunnel = self._tunnel
        if tunnel is not None:
            try:
                statuses = tunnel.url_status()
                self._last_url_status = {s["url"].rstrip("/"): s for s in statuses}
                if hasattr(self, "url_status_frame"):
                    self._build_url_status()
            except Exception:
                pass
        self.root.after(1500, self._schedule_url_status)

    def _start_config_watcher(self):
        self._stop_config_watcher()
        if not os.path.exists(self.config_path):
            return
        handler = ConfigFileHandler(self.config_path, self.root, self._on_config_changed)
        self._observer = Observer()
        self._observer.schedule(handler, path=os.path.dirname(os.path.abspath(self.config_path)),
                                recursive=False)
        self._observer.start()

    def _stop_config_watcher(self):
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=2)
        self._observer = None

    def _on_config_changed(self):
        try:
            mtime = os.path.getmtime(self.config_path)
            if mtime <= self._config_mtime:
                return
            self._config_mtime = mtime
            with open(self.config_path, "r", encoding="utf-8") as f:
                new_cfg = yaml.safe_load(f)
            if new_cfg:
                level = getattr(logging, str(new_cfg.get("logging", {}).get("level", "INFO")).upper(),
                                logging.INFO)
                logging.getLogger().setLevel(level)
                direct = {k: v for k, v in new_cfg.items() if k in ("client", "security", "logging")}
                if direct and self._tunnel:
                    self._tunnel.apply_config(direct)
                self._log("Config reloaded", "INFO")
        except Exception as e:
            self._log(f"Config reload error: {e}", "WARNING")

    def _update_server_display(self):
        try:
            client_cfg = self.engine_cfg.get("client", {})
            self._log(f"Servers: {', '.join(self.server_urls[:2])}"
                      if self.server_urls else "No server URLs", "DEBUG")
        except Exception:
            pass

    def _check_started(self):
        if self.running and self._tunnel:
            proxy_status = self._verify_system_proxy()
            self.info_label.configure(
                text=f"SK5:{self.socks_port}  HTTP:{self.http_port}  PRX:{proxy_status}")
            self.proxy_indicator.configure(
                text=f"PROXY: {proxy_status}",
                fg=FG_GREEN if proxy_status == "SET" else FG_RED)

    def _verify_system_proxy(self) -> str:
        if sys.platform != "win32":
            return "N/A"
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if not enabled:
                    return "DISABLED"
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                if "127.0.0.1" in server and str(self.http_port) in server:
                    return "SET"
                elif server:
                    return f"OTHER: {server}"
        except Exception:
            return "UNKNOWN"
        return "UNKNOWN"

    def _stop(self):
        self.running = False
        self.start_btn.configure(text="Connect", bg=BTN_ON, fg="white")
        self._update_status(False)
        self.info_label.configure(text=tr("Disconnected.", "Отключено."))
        self._log("VPN stopping...", "INFO")

        set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, False)
        self._log("System proxy cleared.", "INFO")
        self._last_url_status = {}

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self._loop = None
        self._tunnel = None

    def _run_loop(self):
        loop = self._loop
        asyncio.set_event_loop(loop)
        poll_task = None
        socks_server = None
        http_server = None
        try:
            cfg = self.cfg.engine_config(self.active_profile)
            self._tunnel = ClientTunnel(cfg)
            self._tunnel.set_log_callback(lambda m: self._log(m, "INFO"))
            self._tunnel._start_dns_relay()

            poll_task = loop.create_task(self._tunnel.poll_loop())
            socks_server, http_server = loop.run_until_complete(self._start_servers_and_wait())

            if socks_server is None or http_server is None:
                self._log("Failed to bind proxy servers", "ERROR")
                return

            # Системный прокси ставим только в VPN-режиме профиля: в режиме
            # Proxy пользователь сам настраивает приложения на SOCKS5.
            use_system_proxy = (sys.platform == "win32"
                                and self.active_profile
                                and self.active_profile["mode"] == "vpn"
                                and self.socks_host in ("0.0.0.0", "127.0.0.1", "localhost"))
            if use_system_proxy:
                set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, True)

            loop.run_forever()
        except Exception as e:
            self._log(f"FATAL: {e}", "ERROR")
        finally:
            try:
                if socks_server:
                    socks_server.close()
                    loop.run_until_complete(socks_server.wait_closed())
            except Exception:
                pass
            try:
                if http_server:
                    http_server.close()
                    loop.run_until_complete(http_server.wait_closed())
            except Exception:
                pass
            try:
                if self._tunnel:
                    loop.run_until_complete(self._tunnel.stop())
            except Exception:
                pass
            try:
                if poll_task:
                    poll_task.cancel()
            except Exception:
                pass

    async def _start_servers_and_wait(self):
        socks_server = None
        http_server = None
        try:
            socks_server = await asyncio.start_server(
                lambda r, w: handle_socks_client(self._tunnel, r, w),
                self.socks_host, self.socks_port, reuse_address=True)
            self._log(f"SOCKS5 listening on {self.socks_host}:{self.socks_port}", "INFO")
        except OSError as e:
            self._log(f"SOCKS5 bind failed: {e}", "ERROR")

        try:
            http_server = await asyncio.start_server(
                lambda r, w: handle_http_client(self._tunnel, r, w),
                self.socks_host, self.http_port, reuse_address=True)
            self._log(f"HTTP CONNECT proxy listening on {self.socks_host}:{self.http_port}", "INFO")
        except OSError as e:
            self._log(f"HTTP proxy bind failed: {e}", "ERROR")

        return socks_server, http_server

    def _update_status(self, connected: bool):
        color = FG_GREEN if connected else FG_RED
        self.status_dot.itemconfig(self._dot_id, fill=color)
        self.status_label.configure(text="ONLINE" if connected else "OFFLINE", fg=color)

    # ══════════════════════════════════════════════════════════════════
    #  Логи
    # ══════════════════════════════════════════════════════════════════

    def _log(self, msg: str, level: str = "INFO"):
        # Туннель живёт в своём потоке и зовёт лог-колбэк оттуда: tkinter
        # нельзя трогать из чужого потока, поэтому перепланируем в main.
        if threading.current_thread() is not threading.main_thread():
            try:
                self.root.after(0, lambda: self._log(msg, level))
            except Exception:
                pass
            return
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        for widget in (self.log_text, getattr(self, "settings_log", None)):
            if widget is None:
                continue
            try:
                widget.configure(state="normal")
                widget.insert(tk.END, line + "\n", level)
                widget.see(tk.END)
                widget.configure(state="disabled")
                lines = int(widget.index("end-1c").split(".")[0])
                if lines > 2000:
                    widget.configure(state="normal")
                    widget.delete("1.0", f"{lines - 1500}.0")
                    widget.configure(state="disabled")
            except Exception:
                pass

    def _setup_logging(self):
        level_name = self.cfg.engine_config().get("logging", {}).get("level", "INFO")
        level = getattr(logging, str(level_name).upper(), logging.INFO)
        handler = TkLogHandler(self.log_text)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                                                datefmt="%H:%M:%S"))
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        root_logger.addHandler(handler)

    # ── Жизненный цикл ──

    def run(self):
        self._setup_logging()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self._on_hide()

    def _quit_app(self):
        self._stop_config_watcher()
        if hasattr(self, "_tray") and self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
        if self.running:
            self._stop()
        self.root.destroy()


# ══════════════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Desktop VPN Client — GUI")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml (migration source)")
    parser.add_argument("--profiles", default="", help="path to profiles.json (default: next to config)")
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    base_dir = os.path.dirname(config_path) or "."
    profiles_path = args.profiles or os.path.join(base_dir, "profiles.json")

    store = DesktopConfig(base_dir)
    if args.profiles:
        store = DesktopConfig(os.path.dirname(os.path.abspath(profiles_path)) or ".")
    # Миграция: если профилей нет — создаём из config.yaml.
    store.seed_from_yaml(config_path)
    store.ensure_profiles()

    app = VpnGui(store, config_path)
    app.run()


if __name__ == "__main__":
    main()
