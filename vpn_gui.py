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
import queue
import socket
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from typing import Optional

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image, ImageDraw

# ── Импорт движка из общих модулей ──
from tunnel import ClientTunnel
from socks5_server import handle_socks_client
from desktop_client import (handle_http_client, set_system_proxy_windows,
                            get_system_proxy_windows, restore_system_proxy_windows)
from desktop_config import DesktopConfig, default_profile_config
from connection_test import test_profile
import tun_mode


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
#  Один экземпляр приложения
# ══════════════════════════════════════════════════════════════════════

INSTANCE_PORT = 47654


def _dialogs_allowed() -> bool:
    """Модальные окна — только в оконной сборке (pythonw/exe).

    В консольных прогонах (smoke-тесты) stdout есть, и диалог заблокировал
    бы автоматику: там предупреждение уходит в лог и подсказку.
    """
    return sys.stdout is None or os.environ.get("VPN_GUI_DIALOGS") == "1"


def _raise_existing_instance(timeout: float = 1.5) -> bool:
    """Если приложение уже запущено — просим его показать окно."""
    try:
        with socket.create_connection(("127.0.0.1", INSTANCE_PORT),
                                      timeout=timeout) as sock:
            sock.sendall(b"show\n")
            sock.settimeout(timeout)
            return sock.recv(16).startswith(b"ok")
    except OSError:
        return False


# ══════════════════════════════════════════════════════════════════════
#  Цветовая палитра — Soft Dark
# ══════════════════════════════════════════════════════════════════════

BG_MAIN     = "#1e1e2e"
BG_PANEL    = "#252536"
BG_CARD     = "#262637"
BG_CARD_ACTIVE = "#1c2b4a"
BG_HOVER    = "#2e2e42"
BG_LOG      = "#171725"
BG_INPUT    = "#2d2d40"
FG_TEXT     = "#cdd6f4"
FG_LABEL    = "#8a8fa7"
FG_DIM      = "#6c7086"
FG_GREEN    = "#a6e3a1"
FG_RED      = "#f38ba8"
FG_BLUE     = "#89b4fa"
FG_AMBER    = "#f9e2af"
BORDER      = "#45475a"
BORDER_SOFT = "#34344c"
BTN_ON      = "#2f9e44"
BTN_OFF     = "#d20f39"
BTN_HOVER_ON = "#2b8a3e"
BTN_HOVER_OFF = "#b80d32"
BTN_ACCENT  = "#2563eb"
BTN_ACCENT_HOVER = "#1d4ed8"


def _mix(color_a: str, color_b: str, t: float) -> str:
    """Смешивает два цвета #rrggbb. t=0 → color_a, t=1 → color_b."""
    t = max(0.0, min(1.0, t))
    a = [int(color_a[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(color_b[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(int(x + (y - x) * t) for x, y in zip(a, b))


def _setup_theme(root: tk.Tk) -> None:
    """Тёмные ttk-стили: без нативного светлого вида у скроллбаров/списков."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    style.configure(
        "Slim.Vertical.TScrollbar", gripcount=0, width=9, arrowsize=10,
        background=BG_PANEL, troughcolor=BG_MAIN, bordercolor=BG_MAIN,
        darkcolor=BG_PANEL, lightcolor=BG_PANEL, arrowcolor=FG_DIM,
    )
    style.map(
        "Slim.Vertical.TScrollbar",
        background=[("active", BORDER), ("pressed", BTN_ACCENT)],
        arrowcolor=[("active", FG_TEXT)],
    )
    style.configure(
        "TCombobox", fieldbackground=BG_INPUT, background=BG_INPUT,
        foreground=FG_TEXT, arrowcolor=FG_LABEL, bordercolor=BORDER,
        lightcolor=BG_INPUT, darkcolor=BG_INPUT, padding=6,
        selectbackground=BG_INPUT, selectforeground=FG_TEXT,
        insertcolor=FG_TEXT,
    )
    style.map(
        "TCombobox",
        fieldbackground=[("readonly", BG_INPUT), ("disabled", BG_PANEL)],
        foreground=[("readonly", FG_TEXT), ("disabled", FG_DIM)],
        selectbackground=[("readonly", BG_INPUT)],
        selectforeground=[("readonly", FG_TEXT)],
        bordercolor=[("focus", BTN_ACCENT)],
        arrowcolor=[("active", FG_TEXT)],
    )
    style.configure("TCheckbutton", background=BG_MAIN, foreground=FG_TEXT,
                    indicatorcolor=BG_INPUT, focuscolor=BG_MAIN)
    style.map("TCheckbutton",
              background=[("active", BG_MAIN)],
              foreground=[("active", FG_TEXT)],
              indicatorcolor=[("selected", BTN_ACCENT)])

    root.option_add("*TCombobox*Listbox.background", BG_INPUT)
    root.option_add("*TCombobox*Listbox.foreground", FG_TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", BTN_ACCENT)
    root.option_add("*TCombobox*Listbox.selectForeground", "white")
    root.option_add("*TCombobox*Listbox.borderWidth", 0)
    root.option_add("*Scrollbar.background", BG_PANEL)
    root.option_add("*Scrollbar.troughcolor", BG_MAIN)
    root.option_add("*Scrollbar.activebackground", BORDER)
    root.option_add("*Scrollbar.highlightThickness", 0)
    root.option_add("*Scrollbar.borderWidth", 0)
    root.option_add("*Scrollbar.width", 10)
    root.option_add("*Menu.background", BG_PANEL)
    root.option_add("*Menu.foreground", FG_TEXT)
    root.option_add("*Menu.activeBackground", BTN_ACCENT)
    root.option_add("*Menu.activeForeground", "white")
    root.option_add("*Menu.borderWidth", 0)
    root.option_add("*Menu.relief", "flat")

    # Один общий обработчик колеса на всё приложение: находит ScrollFrame
    # под курсором (включая дочерние виджеты) и крутит именно его.
    root.bind_all("<MouseWheel>", _dispatch_wheel, add="+")


def _apply_dark_titlebar(win: tk.Toplevel) -> None:
    """Тёмный заголовок окна в Windows 10/11 (аккуратно, без падений)."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        win.update_idletasks()
        hwnd = ctypes.windll.user32.GetParent(win.winfo_id()) or win.winfo_id()
        enabled = ctypes.c_int(1)
        # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Win11), 19 — старое имя.
        for attr in (20, 19):
            ctypes.windll.dwmapi.DwmSetWindowAttribute(
                hwnd, attr, ctypes.byref(enabled), ctypes.sizeof(enabled))
    except Exception:
        pass


def _button(parent, text, command, kind="ghost", font=None,
            padx=12, pady=6):
    """Единый вид кнопок: primary / danger / ghost / link."""
    if kind == "primary":
        bg, fg, active_bg = BTN_ACCENT, "white", BTN_ACCENT_HOVER
    elif kind == "danger":
        bg, fg, active_bg = BTN_OFF, "white", BTN_HOVER_OFF
    elif kind == "link":
        bg, fg, active_bg = parent.cget("bg"), FG_BLUE, parent.cget("bg")
    else:
        bg, fg, active_bg = BG_INPUT, FG_TEXT, BORDER
    return tk.Button(
        parent, text=text, command=command, font=font or ("Segoe UI", 9),
        bg=bg, fg=fg, relief=tk.FLAT, bd=0, padx=padx, pady=pady,
        cursor="hand2", activebackground=active_bg, activeforeground="white",
        highlightthickness=0,
    )


# ══════════════════════════════════════════════════════════════════════
#  Логгер → tkinter виджет
# ══════════════════════════════════════════════════════════════════════

class TkLogHandler(logging.Handler):
    """Потокобезопасный хендлер: копит строки, а в виджет пишет главный поток.

    Вызывать `widget.after()` из рабочего потока на Windows нельзя —
    получаем «main thread is not in main loop». Поэтому emit только
    складывает строки в очередь, а `flush_pending()` дергает GUI.
    """

    def __init__(self, log_widget: tk.Text):
        super().__init__()
        self.widget = log_widget
        self._queue: list[str] = []

    def emit(self, record):
        try:
            self._queue.append(self.format(record))
        except Exception:
            pass

    def flush_pending(self):
        if not self._queue:
            return
        widget = self.widget
        try:
            at_bottom = widget.yview()[1] >= 0.999
            widget.configure(state="normal")
            for msg in self._queue:
                widget.insert(tk.END, msg + "\n")
            self._queue.clear()
            lines = int(widget.index("end-1c").split(".")[0])
            if lines > 2000:
                widget.delete("1.0", f"{lines - 1500}.0")
            if at_bottom:
                widget.see(tk.END)
            widget.configure(state="disabled")
        except Exception:
            self._queue.clear()


# ══════════════════════════════════════════════════════════════════════
#  Watchdog handler для отслеживания изменений config.yaml
# ══════════════════════════════════════════════════════════════════════

class ConfigFileHandler(FileSystemEventHandler):
    """Срабатывает при изменении config.yaml — планирует callback в main thread."""

    def __init__(self, config_path: str, post, callback):
        super().__init__()
        self._config_path = os.path.abspath(config_path)
        self._post = post
        self._callback = callback
        self._last_event = 0

    def on_modified(self, event):
        if os.path.abspath(event.src_path) == self._config_path:
            now = time.time()
            if now - self._last_event > 1.0:
                self._last_event = now
                self._post(self._callback)


# ══════════════════════════════════════════════════════════════════════
#  Хелперы UI
# ══════════════════════════════════════════════════════════════════════

_SCROLL_FRAMES: list = []


class ScrollFrame(tk.Frame):
    """Прокручиваемый контейнер: кладите виджеты в `.inner`.

    Колесо мыши работает и над дочерними виджетами: один общий обработчик
    находит ближайший ScrollFrame под курсором.
    """

    def __init__(self, parent, bg=BG_MAIN, **kwargs):
        super().__init__(parent, bg=bg, **kwargs)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.vbar = ttk.Scrollbar(
            self, orient="vertical", command=self.canvas.yview,
            style="Slim.Vertical.TScrollbar")
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._window = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")

        self.inner.bind("<Configure>", self._on_inner)
        self.canvas.bind("<Configure>", self._on_canvas)
        self.canvas.configure(yscrollcommand=self.vbar.set)

        self.canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.vbar.pack(side=tk.RIGHT, fill=tk.Y)
        _SCROLL_FRAMES.append(self)

    def _on_inner(self, _e=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas(self, event=None):
        self.canvas.itemconfigure(self._window, width=self.canvas.winfo_width())

    def save_pos(self):
        try:
            return self.canvas.yview()[0]
        except tk.TclError:
            return 0.0

    def destroy(self):
        try:
            _SCROLL_FRAMES.remove(self)
        except ValueError:
            pass
        super().destroy()


def _dispatch_wheel(event):
    try:
        widget = event.widget.winfo_containing(event.x_root, event.y_root)
    except Exception:
        return None
    # Текстовые поля, списки и комбобоксы крутятся сами — не дублируем.
    if isinstance(widget, (tk.Text, tk.Listbox, ttk.Combobox, ttk.Treeview)):
        return None
    while widget is not None:
        if widget in _SCROLL_FRAMES:
            steps = -int(event.delta / 120)
            if steps == 0:
                steps = -1 if event.delta > 0 else 1
            try:
                widget.canvas.yview_scroll(steps, "units")
            except tk.TclError:
                pass
            return "break"
        widget = getattr(widget, "master", None)
    return None


class ChipGroup(tk.Frame):
    """Группа «чипов» с одним выбранным значением.

    В отличие от одноразовых кнопок, подсветка обновляется сразу —
    поэтому выбор GET/POST и body/header видно без перестройки окна.
    """

    def __init__(self, parent, options, value=None, command=None, bg=BG_MAIN,
                 font=None, gap=6, padx=12, pady=4):
        super().__init__(parent, bg=bg)
        self._command = command
        self._buttons: dict[str, tk.Button] = {}
        self._value = None
        self._bg = bg
        selected = font or ("Segoe UI", 9)

        for val, label in options:
            btn = tk.Button(
                self, text=label, font=selected, relief=tk.FLAT, bd=0,
                padx=padx, pady=pady, cursor="hand2", highlightthickness=0,
                activeforeground="white",
                command=lambda v=val: self._click(v),
            )
            btn.pack(side=tk.LEFT, padx=(0, gap))
            self._buttons[val] = btn

        first = options[0][0] if options else None
        self.set(value if value is not None else first, notify=False)

    def _click(self, val):
        if val == self._value:
            return
        self.set(val)
        if self._command:
            self._command(val)

    def set(self, value, notify=True):
        self._value = value
        for val, btn in self._buttons.items():
            is_selected = (val == value)
            btn.configure(
                bg=(BTN_ACCENT if is_selected else BG_INPUT),
                fg=("white" if is_selected else FG_TEXT),
                activebackground=(BTN_ACCENT_HOVER if is_selected else BORDER))

    def get(self):
        return self._value

    def set_enabled(self, value, enabled=True):
        btn = self._buttons.get(value)
        if btn is not None:
            btn.configure(state=(tk.NORMAL if enabled else tk.DISABLED),
                          disabledforeground=FG_DIM, cursor=("hand2" if enabled else "arrow"))


class Check(tk.Frame):
    """Тёмный чекбокс: нативный tk.Checkbutton на Windows рисует светлый квадрат."""

    def __init__(self, parent, text, variable, command=None, bg=BG_MAIN,
                 font=None):
        super().__init__(parent, bg=bg)
        self.var = variable
        self._command = command
        self.box = tk.Canvas(self, width=17, height=17, bg=bg,
                             highlightthickness=0, bd=0, cursor="hand2")
        self.box.pack(side=tk.LEFT)
        self._rect = self.box.create_rectangle(3, 3, 15, 15, outline=BORDER,
                                               fill=BG_INPUT, width=1)
        self._tick = self.box.create_line(6, 9, 8, 12, 13, 5, fill="white",
                                          width=2, capstyle=tk.ROUND,
                                          state="hidden")
        self.label = tk.Label(self, text=text, font=font or ("Segoe UI", 9),
                              bg=bg, fg=FG_TEXT, cursor="hand2")
        self.label.pack(side=tk.LEFT, padx=(7, 0))
        for widget in (self, self.box, self.label):
            widget.bind("<Button-1>", self._toggle)
        self._refresh()

    def _toggle(self, _e=None):
        self.var.set(not bool(self.var.get()))
        self._refresh()
        if self._command is not None:
            self._command()

    def _refresh(self):
        on = bool(self.var.get())
        self.box.itemconfigure(self._rect,
                               fill=(BTN_ACCENT if on else BG_INPUT),
                               outline=(BTN_ACCENT if on else BORDER))
        self.box.itemconfigure(self._tick, state=("normal" if on else "hidden"))

    # Совместимость с tk.Checkbutton на случай внешних вызовов.
    def select(self):
        self.var.set(True)
        self._refresh()

    def deselect(self):
        self.var.set(False)
        self._refresh()

    def invoke(self):
        self._toggle()


class PowerButton(tk.Canvas):
    """Большая круглая кнопка подключения, нарисованная на Canvas.

    Сохраняет привычный API: configure(text=..., state=..., on=...) и
    cget("text")/cget("state"), чтобы остальной код работал без изменений.
    """

    HEIGHT = 212
    RADIUS = 74

    def __init__(self, parent, command=None, bg=BG_MAIN, text="Connect", **kwargs):
        super().__init__(parent, bg=bg, highlightthickness=0, bd=0,
                         width=340, height=self.HEIGHT, **kwargs)
        self._command = command
        self._text = text
        self._state = "normal"
        self._on = False
        self._hover = False
        self.configure(cursor="hand2")
        self.bind("<Configure>", lambda _e: self._redraw())
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)
        self.bind("<Button-1>", self._click)

    # ── Совместимость с tk.Button ──

    def configure(self, cnf=None, **kw):
        if isinstance(cnf, dict):
            kw = {**cnf, **kw}
            cnf = None
        special = {}
        for key in ("text", "state", "on", "command"):
            if key in kw:
                special[key] = kw.pop(key)
        if cnf is not None:
            return super().configure(cnf, **kw)
        if kw:
            super().configure(**kw)
        if "command" in special:
            self._command = special["command"]
        if "text" in special:
            self._text = str(special["text"])
        if "on" in special:
            self._on = bool(special["on"])
        if "state" in special:
            self._state = str(special["state"])
        super().configure(cursor=("arrow" if self._state == "disabled" else "hand2"))
        self._redraw()

    def cget(self, key):
        if key == "text":
            return self._text
        if key == "state":
            return self._state
        if key == "on":
            return self._on
        return super().cget(key)

    def __getitem__(self, key):
        return self.cget(key)

    def invoke(self):
        self._click()

    # ── Взаимодействие ──

    def _enter(self, _e=None):
        self._hover = True
        self._redraw()

    def _leave(self, _e=None):
        self._hover = False
        self._redraw()

    def _click(self, _e=None):
        if self._state == "disabled" or self._command is None:
            return
        self._command()

    # ── Отрисовка ──

    def _redraw(self):
        self.delete("all")
        width = max(self.winfo_width(), 220)
        cx = width / 2
        cy = 92
        r = self.RADIUS

        if self._state == "disabled":
            base, accent = "#4b4b60", "#6c7086"
        elif self._on:
            base, accent = BTN_ON, FG_GREEN
        else:
            base, accent = BTN_ACCENT, FG_BLUE
        if self._hover and self._state != "disabled":
            base = _mix(base, "#ffffff", 0.12)

        # Мягкое свечение вокруг кнопки.
        for extra, strength in ((26, 0.07), (16, 0.11), (8, 0.16)):
            self.create_oval(cx - r - extra, cy - r - extra,
                             cx + r + extra, cy + r + extra,
                             fill=_mix(BG_MAIN, accent, strength), outline="")

        # Радиальный «градиент»: несколько вложенных окружностей.
        steps = 18
        for i in range(steps):
            rad = r - (r * 0.55) * (i / steps)
            color = _mix(base, "#ffffff", 0.22 * (i / steps))
            self.create_oval(cx - rad, cy - rad, cx + rad, cy + rad,
                             fill=color, outline="")

        # Значок питания.
        glyph = r * 0.36
        self.create_arc(cx - glyph, cy - glyph, cx + glyph, cy + glyph,
                        start=315, extent=270, style="arc",
                        outline="white", width=6)
        self.create_line(cx, cy - glyph - 12, cx, cy - glyph * 0.15,
                         fill="white", width=6, capstyle=tk.ROUND)

        # Подпись под кнопкой.
        self.create_text(cx, cy + r + 24, text=self._text.upper(),
                         fill=(accent if self._on else FG_TEXT),
                         font=("Segoe UI", 11, "bold"))


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
        # TUN-режим: клиент elevated-помощника и признак поднятого адаптера.
        self._tun_helper: tun_mode.TunHelperClient | None = None
        self._tun_active = False
        self._tun_error = ""
        self._tun_route_busy = False
        self._phys_adapter: dict | None = None
        # Системный прокси ставим только сами и только если включён режим
        # Proxy / VPN (system proxy); перед этим запоминаем чужой прокси,
        # чтобы вернуть его на Disconnect.
        self._proxy_snapshot: dict = {}
        self._proxy_applied = False
        self._proxy_lock = threading.Lock()
        # Disconnect/Quit выполняются в фоновом потоке: остановка помощника
        # включает восстановление DNS через PowerShell и может занять
        # несколько секунд. Держим UI отзывчивым.
        self._stopping = False
        self._closing = False
        self._pump_stopped = False
        # Очередь задач в главный поток: туннель, тесты, импорт и трей
        # работают в своих потоках, а tkinter трогать оттуда нельзя —
        # root.after() из чужого потока на Windows падает с
        # «main thread is not in main loop».
        self._main_queue: queue.Queue = queue.Queue()

        # Язык
        L.ru = (self.cfg.get_pref("language", "ru") == "ru")

        self._reload_display_config()

        # ── Tk root ──
        self.root = tk.Tk()
        self.root.title("Short Polling VPN")
        self.root.configure(bg=BG_MAIN)
        self.root.resizable(True, True)
        _setup_theme(self.root)
        self.root.minsize(540, 700)
        self._center_root(600, 860)

        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self._settings_win: Optional[tk.Toplevel] = None
        self._build_ui()
        self._start_instance_server()
        self._start_config_watcher()
        self._create_tray_icon()
        self._refresh_profiles()
        # Разбор очереди задач в главный поток (логи, тесты, импорт, трей).
        self._pump_main_queue()
        _apply_dark_titlebar(self.root)

    def _center_root(self, width: int, height: int) -> None:
        try:
            sw = self.root.winfo_screenwidth()
            sh = self.root.winfo_screenheight()
        except tk.TclError:
            return
        x = max(0, (sw - width) // 2)
        y = max(0, (sh - height) // 3)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _center_window(self, win: tk.Toplevel, width: int, height: int) -> None:
        try:
            self.root.update_idletasks()
            rx, ry = self.root.winfo_rootx(), self.root.winfo_rooty()
            rw, rh = self.root.winfo_width(), self.root.winfo_height()
            x = max(0, rx + (rw - width) // 2)
            y = max(0, ry + (rh - height) // 3)
        except tk.TclError:
            x = y = 80
        win.geometry(f"{width}x{height}+{x}+{y}")

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
        self.FONT    = ("Segoe UI", 10)
        self.FONT_B  = ("Segoe UI", 10, "bold")
        self.FONT_S  = ("Segoe UI", 9)
        self.FONT_XS = ("Segoe UI", 8)
        self.FONT_L  = ("Segoe UI", 16, "bold")
        self.FONT_H  = ("Segoe UI", 12, "bold")

        self._profiles_sig = None
        self._profile_widgets: list[dict] = []
        self._profile_menu = None
        self._sub_sig = None
        self._url_status_sig = None
        self._url_rows: list[dict] = []

        # ═══ Заголовок ═══
        header = tk.Frame(root, bg=BG_MAIN)
        header.pack(fill=tk.X, padx=16, pady=(12, 2))

        logo = tk.Canvas(header, width=36, height=36, bg=BG_MAIN, highlightthickness=0)
        logo.pack(side=tk.LEFT)
        logo.create_oval(2, 2, 34, 34, fill=BTN_ACCENT, outline="")
        logo.create_arc(12, 12, 24, 24, start=315, extent=270, style="arc",
                        outline="white", width=2)
        logo.create_line(18, 9, 18, 17, fill="white", width=2)

        title_box = tk.Frame(header, bg=BG_MAIN)
        title_box.pack(side=tk.LEFT, padx=(10, 0))
        tk.Label(title_box, text="Short Polling VPN", font=self.FONT_H, bg=BG_MAIN,
                 fg=FG_TEXT).pack(anchor=tk.W)
        tk.Label(title_box, text=tr("Encrypted tunnel", "Зашифрованный туннель"),
                 font=self.FONT_XS, bg=BG_MAIN, fg=FG_DIM).pack(anchor=tk.W)

        self.settings_btn = _button(
            header, "\u2699  " + tr("Settings", "Настройки"), self._open_settings,
            font=self.FONT_S, padx=12, pady=6)
        self.settings_btn.pack(side=tk.RIGHT)

        self.status_frame = tk.Frame(header, bg=BG_INPUT)
        self.status_frame.pack(side=tk.RIGHT, padx=(0, 8))
        self.status_dot = tk.Canvas(self.status_frame, width=10, height=10,
                                    bg=BG_INPUT, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(10, 5), pady=7)
        self._dot_id = self.status_dot.create_oval(1, 1, 9, 9, fill=FG_RED, outline="")
        self.status_label = tk.Label(self.status_frame, text="OFFLINE",
                                     font=("Segoe UI", 9, "bold"), bg=BG_INPUT, fg=FG_RED)
        self.status_label.pack(side=tk.LEFT, padx=(0, 10))

        # ═══ Прокручиваемая область ═══
        scroll_outer = tk.Frame(root, bg=BG_MAIN)
        scroll_outer.pack(fill=tk.BOTH, expand=True, padx=12, pady=(4, 8))
        self._scroll = ScrollFrame(scroll_outer, bg=BG_MAIN)
        self._scroll.pack(fill=tk.BOTH, expand=True)
        self.body = self._scroll.inner

        # ── Большая кнопка подключения ──
        hero = tk.Frame(self.body, bg=BG_MAIN)
        hero.pack(fill=tk.X, pady=(2, 0))
        self.start_btn = PowerButton(hero, command=self._on_toggle, bg=BG_MAIN,
                                     text=tr("Connect", "Подключить"))
        self.start_btn.pack(fill=tk.X)
        self.hero_hint = tk.Label(
            hero, text=tr("Tap to connect", "Нажмите, чтобы подключиться"),
            font=self.FONT_S, bg=BG_MAIN, fg=FG_DIM)
        self.hero_hint.pack(pady=(0, 4))

        # ── Активный профиль ──
        self.active_card = tk.Frame(self.body, bg=BG_CARD,
                                    highlightbackground=BORDER_SOFT, highlightthickness=1)
        self.active_card.pack(fill=tk.X, pady=(6, 0))
        card_row = tk.Frame(self.active_card, bg=BG_CARD)
        card_row.pack(fill=tk.X, padx=14, pady=10)

        left = tk.Frame(card_row, bg=BG_CARD)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(left, text=tr("Active profile", "Активный профиль").upper(),
                 font=("Segoe UI", 8, "bold"), bg=BG_CARD,
                 fg=FG_DIM).pack(anchor=tk.W)
        self.active_label = tk.Label(left, text="", font=("Segoe UI", 12, "bold"),
                                     bg=BG_CARD, fg=FG_TEXT, anchor=tk.W)
        self.active_label.pack(anchor=tk.W, pady=(1, 0))
        self.active_meta = tk.Label(left, text="", font=self.FONT_XS, bg=BG_CARD,
                                    fg=FG_BLUE, anchor=tk.W)
        self.active_meta.pack(anchor=tk.W)

        self.change_btn = _button(card_row, tr("Change", "Сменить") + "  \u25be",
                                  self._show_profile_menu, font=self.FONT_S,
                                  padx=12, pady=6)
        self.change_btn.pack(side=tk.RIGHT)

        # ── Порт / режим ──
        self.info_bar = tk.Frame(self.body, bg=BG_PANEL,
                                 highlightbackground=BORDER_SOFT, highlightthickness=1)
        self.info_bar.pack(fill=tk.X, pady=(8, 0))
        self.info_label = tk.Label(self.info_bar, text="", font=self.FONT_XS,
                                   bg=BG_PANEL, fg=FG_LABEL, anchor=tk.W)
        self.info_label.pack(side=tk.LEFT, padx=12, pady=6)
        self.proxy_indicator = tk.Label(self.info_bar, text="", font=self.FONT_XS,
                                        bg=BG_PANEL, fg=FG_LABEL)
        self.proxy_indicator.pack(side=tk.RIGHT, padx=12, pady=6)

        # ── Профили ──
        profiles_head = tk.Frame(self.body, bg=BG_MAIN)
        profiles_head.pack(fill=tk.X, pady=(14, 4))
        tk.Label(profiles_head, text=tr("Profiles", "Профили"), font=self.FONT_H,
                 bg=BG_MAIN, fg=FG_TEXT).pack(side=tk.LEFT)
        _button(profiles_head, tr("Manage", "Управление"),
                lambda: self._open_settings(tab="general"),
                kind="link", font=self.FONT_S, padx=4, pady=2).pack(side=tk.RIGHT)
        self.profiles_frame = tk.Frame(self.body, bg=BG_MAIN)
        self.profiles_frame.pack(fill=tk.X)

        # ── Подписка ──
        self.sub_card = tk.Frame(self.body, bg=BG_CARD,
                                 highlightbackground=BORDER_SOFT, highlightthickness=1)
        self.sub_card.pack(fill=tk.X, pady=(14, 0))

        # ── Лог ──
        log_head = tk.Frame(self.body, bg=BG_MAIN)
        log_head.pack(fill=tk.X, pady=(16, 2))
        tk.Label(log_head, text=tr("Log", "Лог"), font=self.FONT_B, bg=BG_MAIN,
                 fg=FG_LABEL).pack(side=tk.LEFT)
        self.log_toggle_btn = _button(log_head, tr("Show", "Показать"),
                                      self._toggle_log, kind="link",
                                      font=self.FONT_S, padx=4, pady=2)
        self.log_toggle_btn.pack(side=tk.RIGHT)

        self.log_box = tk.Frame(self.body, bg=BG_LOG,
                                highlightbackground=BORDER_SOFT, highlightthickness=1)
        log_wrap, self.log_text = self._make_log_text(self.log_box, height=10)
        log_wrap.pack(fill=tk.BOTH, expand=True, padx=1, pady=1)
        self._log_visible = False

    def _make_log_text(self, parent, height=None):
        """Тёмный лог: Text + ttk-скроллбар (штатный у scrolledtext светлый)."""
        wrap = tk.Frame(parent, bg=BG_LOG)
        text = tk.Text(wrap, wrap=tk.WORD, font=("Consolas", 9), bg=BG_LOG,
                       fg=FG_TEXT, insertbackground=FG_TEXT, relief=tk.FLAT,
                       state="disabled", bd=0, highlightthickness=0,
                       selectbackground=FG_BLUE, selectforeground="white",
                       padx=6, pady=4)
        vbar = ttk.Scrollbar(wrap, orient="vertical", command=text.yview,
                             style="Slim.Vertical.TScrollbar")
        text.configure(yscrollcommand=vbar.set)
        if height:
            text.configure(height=height)
        text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vbar.pack(side=tk.RIGHT, fill=tk.Y)
        for tag, color in (("INFO", FG_TEXT), ("WARNING", FG_AMBER),
                            ("ERROR", FG_RED), ("DEBUG", FG_DIM)):
            text.tag_config(tag, foreground=color)
        return wrap, text

    def _toggle_log(self):
        self._log_visible = not self._log_visible
        if self._log_visible:
            self.log_box.pack(fill=tk.BOTH, expand=True, pady=(2, 8))
            self.log_toggle_btn.configure(text=tr("Hide", "Скрыть"))
            self.log_text.see(tk.END)
        else:
            self.log_box.pack_forget()
            self.log_toggle_btn.configure(text=tr("Show", "Показать"))

    def _show_profile_menu(self):
        menu = self._profile_menu
        if menu is None:
            return
        try:
            x = self.change_btn.winfo_rootx()
            y = self.change_btn.winfo_rooty() + self.change_btn.winfo_height()
            menu.tk_popup(x, y)
        finally:
            try:
                menu.grab_release()
            except tk.TclError:
                pass


    def _display_host(self):
        if self.socks_host in ("0.0.0.0", ""):
            return "127.0.0.1"
        return self.socks_host

    def _mode_label(self, profile: dict) -> str:
        if profile["mode"] != "vpn":
            return "Proxy"
        backend = profile.get("vpn_backend", "tun")
        return "VPN (TUN)" if backend == "tun" else "VPN (proxy)"

    # ══════════════════════════════════════════════════════════════════
    #  Профили и подписки (главный экран)
    # ══════════════════════════════════════════════════════════════════

    def _refresh_profiles(self):
        """Обновляет главный экран.

        Карточки профилей не пересоздаются, если состав списка не менялся:
        это убирает мерцание и сохраняет позицию прокрутки при выборе профиля.
        """
        self._reload_display_config()
        profile = self.active_profile
        if profile:
            self._set_text(self.active_label, profile["name"])
            self._set_text(self.active_meta, self._mode_label(profile))
        else:
            self._set_text(self.active_label, tr("No profile", "Нет профиля"))
            self._set_text(self.active_meta,
                           tr("Add a subscription below", "Добавьте подписку ниже"))
        self._build_subscription_card()
        self._sync_profiles()
        self._update_idle_info()

    @staticmethod
    def _set_text(widget, text, fg=None):
        """Меняет текст только если он отличается — без лишних перерисовок."""
        try:
            if widget.cget("text") != text:
                widget.configure(text=text)
            if fg is not None and widget.cget("fg") != fg:
                widget.configure(fg=fg)
        except tk.TclError:
            pass

    def _update_idle_info(self):
        if self.running:
            return
        host = self._display_host()
        self._set_text(
            self.info_label,
            f"SOCKS {host}:{self.socks_port}   ·   HTTP {host}:{self.http_port}")
        profile = self.active_profile
        if profile and profile["mode"] == "vpn":
            self._set_text(self.proxy_indicator,
                           self._mode_label(profile).upper(), FG_BLUE)
        else:
            self._set_text(self.proxy_indicator,
                           tr("PROXY MODE", "РЕЖИМ ПРОКСИ"), FG_AMBER)

    def _build_subscription_card(self):
        profile = self.active_profile
        cfg = profile["config"] if profile else default_profile_config()
        sub = cfg.get("subscription", {})
        name = (sub.get("name") or cfg["user"].get("uuid", "")[:8]
                or tr("No subscription", "Нет подписки"))
        signature = (name, sub.get("url", ""), bool(profile))
        if self._sub_sig == signature:
            return
        self._sub_sig = signature

        for w in self.sub_card.winfo_children():
            w.destroy()

        body = tk.Frame(self.sub_card, bg=BG_CARD)
        body.pack(fill=tk.X, padx=14, pady=12)

        top = tk.Frame(body, bg=BG_CARD)
        top.pack(fill=tk.X)
        tk.Label(top, text=tr("Subscription", "Подписка").upper(),
                 font=("Segoe UI", 8, "bold"), bg=BG_CARD,
                 fg=FG_DIM).pack(side=tk.LEFT)
        if sub.get("url"):
            _button(top, tr("Refresh", "Обновить"),
                    lambda u=sub["url"]: self._import_subscription_text(u, select=False),
                    kind="link", font=self.FONT_XS, padx=2, pady=0
                    ).pack(side=tk.RIGHT)

        tk.Label(body, text=name, font=("Segoe UI", 11, "bold"), bg=BG_CARD,
                 fg=FG_TEXT, anchor=tk.W).pack(anchor=tk.W, pady=(2, 0))
        if sub.get("url"):
            tk.Label(body, text=sub["url"], font=self.FONT_XS, bg=BG_CARD,
                     fg=FG_DIM, anchor=tk.W, wraplength=470,
                     justify=tk.LEFT).pack(anchor=tk.W, pady=(1, 0))

        row = tk.Frame(body, bg=BG_CARD)
        row.pack(fill=tk.X, pady=(10, 0))
        _button(row, tr("Add subscription", "Добавить подписку"),
                self._add_subscription_dialog, kind="primary",
                font=self.FONT_S, padx=14).pack(side=tk.LEFT)
        _button(row, tr("From clipboard", "Из буфера"),
                self._import_from_clipboard, font=self.FONT_S).pack(side=tk.LEFT, padx=6)
        _button(row, tr("From file", "Из файла"),
                self._import_from_file, font=self.FONT_S).pack(side=tk.LEFT)

    def _profiles_signature(self):
        groups = self.cfg.group_profiles()
        return tuple(
            (url, (ps[0]["config"]["subscription"].get("name") or ""),
             tuple(p["id"] for p in ps))
            for url, ps in groups
        )

    def _sync_profiles(self):
        groups = self.cfg.group_profiles()
        signature = self._profiles_signature()
        if self._profiles_sig != signature:
            self._profiles_sig = signature
            self._build_profiles_list(groups)
            self._rebuild_profile_menu(groups)
        else:
            self._update_profile_cards()
            menu_var = getattr(self, "_profile_menu_var", None)
            if menu_var is not None:
                menu_var.set(self.cfg.get_active_id())

    def _restore_scroll(self, pos: float):
        def apply():
            try:
                self._scroll.canvas.yview_moveto(pos)
            except tk.TclError:
                pass
        try:
            self.root.after_idle(apply)
        except tk.TclError:
            pass

    def _build_profiles_list(self, groups=None):
        pos = self._scroll.save_pos()
        for w in self.profiles_frame.winfo_children():
            w.destroy()
        self._profile_widgets = []

        groups = groups if groups is not None else self.cfg.group_profiles()
        if not groups:
            tk.Label(self.profiles_frame,
                     text=tr("No profiles yet. Add a subscription below.",
                             "Профилей нет. Добавьте подписку ниже."),
                     font=self.FONT_S, bg=BG_MAIN, fg=FG_LABEL
                     ).pack(anchor=tk.W, pady=8, padx=2)
            self._restore_scroll(pos)
            return

        active_id = self.cfg.get_active_id()

        for sub_url, profiles in groups:
            title = (profiles[0]["config"]["subscription"].get("name")
                     or tr("Local profiles", "Локальные профили"))
            gh = tk.Frame(self.profiles_frame, bg=BG_MAIN)
            gh.pack(fill=tk.X, pady=(8, 3))
            tk.Label(gh, text=title, font=("Segoe UI", 9, "bold"), bg=BG_MAIN,
                     fg=FG_LABEL, anchor=tk.W).pack(side=tk.LEFT, padx=2)
            if sub_url:
                remove = _button(gh, tr("Remove", "Удалить"),
                                 lambda u=sub_url, n=title: self._delete_subscription(u, n),
                                 kind="link", font=self.FONT_XS, padx=4, pady=0)
                remove.configure(fg=FG_RED, activeforeground=FG_RED)
                remove.pack(side=tk.RIGHT, padx=(6, 0))
            _button(gh, tr("Test all", "Тест всех"),
                    lambda ps=profiles: self._test_profiles(ps),
                    kind="link", font=self.FONT_XS, padx=2, pady=0
                    ).pack(side=tk.RIGHT)

            for p in profiles:
                self._build_profile_card(p, p["id"] == active_id)

        self._restore_scroll(pos)

    def _build_profile_card(self, profile: dict, active: bool):
        card = tk.Frame(self.profiles_frame, bg=BG_CARD, highlightthickness=1,
                        highlightbackground=BORDER_SOFT)
        card.pack(fill=tk.X, pady=3)

        inner = tk.Frame(card, bg=BG_CARD)
        inner.pack(fill=tk.X, padx=12, pady=9)

        left = tk.Frame(inner, bg=BG_CARD)
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)

        name_row = tk.Frame(left, bg=BG_CARD)
        name_row.pack(anchor=tk.W)
        dot = tk.Canvas(name_row, width=16, height=16, bg=BG_CARD,
                        highlightthickness=0, bd=0, cursor="hand2")
        dot.pack(side=tk.LEFT, padx=(0, 6))
        dot_id = dot.create_oval(4, 4, 12, 12, fill="", outline="")
        name = tk.Label(name_row, text=profile["name"], font=self.FONT_B,
                        bg=BG_CARD, fg=FG_TEXT, cursor="hand2")
        name.pack(side=tk.LEFT)

        meta = tk.Label(left, text=self._mode_label(profile), font=self.FONT_XS,
                        bg=BG_CARD, fg=FG_LABEL, anchor=tk.W, cursor="hand2")
        meta.pack(anchor=tk.W, padx=(22, 0))

        test = tk.Label(left, text="", font=self.FONT_XS, bg=BG_CARD,
                        fg=FG_LABEL, anchor=tk.W, justify=tk.LEFT, wraplength=285,
                        cursor="hand2")
        test.pack(anchor=tk.W, padx=(22, 0))

        test_btn = _button(inner, tr("Test", "Тест"),
                           lambda p=profile: self._test_profiles([p]),
                           font=self.FONT_XS, padx=10, pady=4)
        test_btn.pack(side=tk.RIGHT, padx=(6, 0))

        select_btn = _button(inner, "", lambda p=profile: self._select_profile(p["id"]),
                             font=self.FONT_XS, padx=10, pady=4)
        select_btn.pack(side=tk.RIGHT)

        entry = {
            "profile": profile, "card": card, "inner": inner, "left": left,
            "name_row": name_row, "dot": dot, "dot_id": dot_id,
            "name": name, "meta": meta,
            "test": test, "test_btn": test_btn, "select_btn": select_btn,
        }
        for widget in (card, inner, left, name_row, dot, name, meta, test):
            widget.bind("<Button-1>",
                        lambda _e, pid=profile["id"]: self._select_profile(pid))
        self._profile_widgets.append(entry)
        self._style_profile_card(entry, active)

    def _style_profile_card(self, entry: dict, active: bool):
        bg = BG_CARD_ACTIVE if active else BG_CARD
        for widget in (entry["card"], entry["inner"], entry["left"],
                       entry["name_row"], entry["dot"], entry["name"],
                       entry["meta"], entry["test"]):
            widget.configure(bg=bg)
        entry["card"].configure(
            highlightbackground=(BTN_ACCENT if active else BORDER_SOFT))
        entry["dot"].itemconfigure(entry["dot_id"],
                                   fill=(FG_GREEN if active else ""),
                                   outline="")
        entry["name"].configure(fg=FG_TEXT)
        entry["select_btn"].configure(
            text=(tr("Active", "Активен") if active else tr("Select", "Выбрать")),
            bg=(BG_INPUT if active else BTN_ACCENT),
            activebackground=(BORDER if active else BTN_ACCENT_HOVER),
            state=(tk.DISABLED if active else tk.NORMAL),
            disabledforeground=FG_BLUE)
        profile = entry["profile"]
        line, color = self._test_line(profile["id"],
                                      self._test_results.get(profile["id"]))
        self._set_text(entry["test"], line, color)

    def _update_profile_cards(self):
        active_id = self.cfg.get_active_id()
        for entry in self._profile_widgets:
            self._style_profile_card(entry, entry["profile"]["id"] == active_id)

    def _rebuild_profile_menu(self, groups=None):
        menu = tk.Menu(self.root, tearoff=0, bg=BG_PANEL, fg=FG_TEXT,
                       activebackground=BTN_ACCENT, activeforeground="white",
                       bd=0, relief=tk.FLAT)
        active_id = self.cfg.get_active_id()
        var = tk.StringVar(value=active_id)
        self._profile_menu_var = var
        groups = groups if groups is not None else self.cfg.group_profiles()
        first = True
        for _sub_url, profiles in groups:
            if not first:
                menu.add_separator()
            first = False
            title = (profiles[0]["config"]["subscription"].get("name")
                     or tr("Local profiles", "Локальные профили"))
            menu.add_command(label=title, state=tk.DISABLED)
            for p in profiles:
                menu.add_radiobutton(
                    label="   " + p["name"], value=p["id"], variable=var,
                    command=lambda pid=p["id"]: self._select_profile(pid))
        self._profile_menu = menu


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
            self._post(self._refresh_profiles)

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
                self._post(self._log, f"OK: {profile['name']}", "INFO")
                self._post(self._refresh_profiles)
        except Exception as exc:
            self._post(self._log, f"Subscription error: {exc}", "ERROR")

    # ══════════════════════════════════════════════════════════════════
    #  Настройки (отдельное окно)
    # ══════════════════════════════════════════════════════════════════

    def _section_label(self, parent, text, pady=(12, 6)):
        row = tk.Frame(parent, bg=BG_MAIN)
        row.pack(fill=tk.X, pady=pady)
        tk.Frame(row, bg=BTN_ACCENT, width=3, height=14).pack(side=tk.LEFT, padx=(0, 8))
        tk.Label(row, text=text.upper(), font=("Segoe UI", 9, "bold"), bg=BG_MAIN,
                 fg=FG_LABEL).pack(side=tk.LEFT)
        return row

    def _divider(self, parent, pady=8):
        tk.Frame(parent, bg=BORDER_SOFT, height=1).pack(fill=tk.X, pady=pady)

    def _open_settings(self, tab: str = "general"):
        if self._settings_win and self._settings_win.winfo_exists():
            self._settings_win.deiconify()
            self._settings_win.lift()
            self._settings_win.focus_force()
            self._select_settings_tab(tab)
            return

        win = tk.Toplevel(self.root)
        win.title(tr("Settings", "Настройки"))
        win.configure(bg=BG_MAIN)
        win.transient(self.root)
        win.protocol("WM_DELETE_WINDOW", self._close_settings)
        self._settings_win = win
        self._center_window(win, 900, 680)
        win.minsize(780, 560)

        # Шапка окна.
        top = tk.Frame(win, bg=BG_MAIN)
        top.pack(fill=tk.X, padx=20, pady=(16, 0))
        tk.Label(top, text=tr("Settings", "Настройки"), font=("Segoe UI", 15, "bold"),
                 bg=BG_MAIN, fg=FG_TEXT).pack(side=tk.LEFT)
        _button(top, "✕", self._close_settings, kind="link",
                font=("Segoe UI", 11), padx=6, pady=2
                ).pack(side=tk.RIGHT)
        tk.Frame(win, bg=BORDER_SOFT, height=1).pack(fill=tk.X, padx=20, pady=(10, 0))

        body = tk.Frame(win, bg=BG_MAIN)
        body.pack(fill=tk.BOTH, expand=True, padx=20, pady=(14, 16))

        # Боковая навигация — крупные и заметные разделы.
        side = tk.Frame(body, bg=BG_PANEL, width=216,
                        highlightbackground=BORDER_SOFT, highlightthickness=1)
        side.pack(side=tk.LEFT, fill=tk.Y)
        side.pack_propagate(False)

        content = tk.Frame(body, bg=BG_MAIN)
        content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(18, 0))

        self._settings_title = tk.Label(content, text="", font=("Segoe UI", 14, "bold"),
                                        bg=BG_MAIN, fg=FG_TEXT, anchor=tk.W)
        self._settings_title.pack(fill=tk.X, pady=(2, 0))
        self._settings_sub = tk.Label(content, text="", font=self.FONT_XS, bg=BG_MAIN,
                                      fg=FG_DIM, anchor=tk.W, justify=tk.LEFT)
        self._settings_sub.pack(fill=tk.X, pady=(2, 10))
        self._settings_body = tk.Frame(content, bg=BG_MAIN)
        self._settings_body.pack(fill=tk.BOTH, expand=True)

        self.tab_general = tk.Frame(self._settings_body, bg=BG_MAIN)
        self.tab_connection = tk.Frame(self._settings_body, bg=BG_MAIN)
        self.tab_logs = tk.Frame(self._settings_body, bg=BG_MAIN)

        nav_defs = (
            ("general", "\u2699", "General", "Общее"),
            ("connection", "\u21c4", "Connection", "Подключение"),
            ("logs", "\u25a4", "Logs", "Логи"),
        )
        self._nav_items = []
        for key, icon, en, ru in nav_defs:
            item = tk.Frame(side, bg=BG_PANEL, cursor="hand2")
            item.pack(fill=tk.X)
            bar = tk.Frame(item, bg=BG_PANEL, width=3)
            bar.pack(side=tk.LEFT, fill=tk.Y)
            label = tk.Label(item, text=f" {icon}    {tr(en, ru)}", font=("Segoe UI", 10),
                             bg=BG_PANEL, fg=FG_LABEL, anchor=tk.W, padx=10, pady=11,
                             cursor="hand2")
            label.pack(side=tk.LEFT, fill=tk.X, expand=True)
            for widget in (item, label):
                widget.bind("<Button-1>",
                            lambda _e, k=key: self._select_settings_tab(k))
            self._nav_items.append(
                {"key": key, "frame": item, "bar": bar, "label": label})

        tk.Label(side, text="Short Polling VPN", font=("Segoe UI", 8),
                 bg=BG_PANEL, fg=FG_DIM).pack(side=tk.BOTTOM, pady=10)
        quit_btn = _button(side, tr("Quit app", "Выход из приложения"),
                           self._quit_app, kind="link",
                           font=self.FONT_S, padx=10, pady=6)
        quit_btn.configure(fg=FG_RED, activeforeground=FG_RED)
        quit_btn.pack(side=tk.BOTTOM, fill=tk.X, pady=(6, 0))

        self._build_general_tab()
        self._build_connection_tab()
        self._build_logs_tab()
        self._select_settings_tab(tab)
        _apply_dark_titlebar(win)

    def _select_settings_tab(self, tab: str):
        if not getattr(self, "_nav_items", None):
            return
        index = {"general": 0, "connection": 1, "logs": 2}.get(tab, 0)
        frames = (self.tab_general, self.tab_connection, self.tab_logs)
        for i, frame in enumerate(frames):
            if i == index:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()
        for i, item in enumerate(self._nav_items):
            active = (i == index)
            bg = BG_INPUT if active else BG_PANEL
            item["frame"].configure(bg=bg)
            item["label"].configure(bg=bg, fg=(FG_TEXT if active else FG_LABEL))
            item["bar"].configure(bg=(BTN_ACCENT if active else BG_PANEL))

        titles = (
            (tr("General", "Общее"),
             tr("Interface language and profile management.",
                "Язык интерфейса и управление профилями.")),
            (tr("Connection", "Подключение"),
             tr("Mode, routing, servers and advanced client options.",
                "Режим, маршрутизация, серверы и дополнительные параметры клиента.")),
            (tr("Logs", "Логи"),
             tr("Live service log of the tunnel and the helper.",
                "Живой сервисный лог туннеля и помощника.")),
        )
        if hasattr(self, "_settings_title"):
            self._settings_title.configure(text=titles[index][0])
            self._settings_sub.configure(text=titles[index][1])
        self._settings_tab = index

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

        wrap = tk.Frame(self.tab_general, bg=BG_MAIN)
        wrap.pack(fill=tk.BOTH, expand=True, padx=2)

        self._section_label(wrap, tr("Language", "Язык"), pady=(2, 6))
        lang = tk.Frame(wrap, bg=BG_MAIN)
        lang.pack(fill=tk.X)
        current = self.cfg.get_pref("language", "ru")
        ChipGroup(lang, [("en", "English"), ("ru", "Русский")], value=current,
                  command=self._set_language, bg=BG_MAIN).pack(side=tk.LEFT)

        self._divider(wrap, pady=12)
        self._section_label(wrap, tr("Profiles", "Профили"), pady=(0, 4))
        self._note(wrap,
                   tr("Each profile stores its own mode, connection and routing settings. Changes apply on reconnect.",
                      "Каждый профиль хранит свой режим, настройки подключения и маршрутизацию. Изменения применяются при переподключении."),
                   pady=(0, 6))

        # Список профилей.
        list_scroll = ScrollFrame(wrap, bg=BG_MAIN)
        list_scroll.pack(fill=tk.BOTH, expand=True)
        list_inner = list_scroll.inner
        self._general_list = list_inner

        active_id = self.cfg.get_active_id()
        for p in self.cfg.load_profiles():
            is_active = p["id"] == active_id
            bg = BG_CARD_ACTIVE if is_active else BG_CARD
            card = tk.Frame(list_inner, bg=bg, highlightthickness=1,
                            highlightbackground=(BTN_ACCENT if is_active else BORDER_SOFT))
            card.pack(fill=tk.X, pady=3)
            row = tk.Frame(card, bg=bg)
            row.pack(fill=tk.X, padx=10, pady=7)
            tk.Label(row, text="\u25cf", font=("Segoe UI", 8), bg=bg,
                     fg=(FG_GREEN if is_active else bg)).pack(side=tk.LEFT, padx=(0, 6))
            tk.Label(row, text=p["name"], font=self.FONT_B, bg=bg,
                     fg=FG_TEXT).pack(side=tk.LEFT)
            tk.Label(row, text=self._mode_label(p), font=self.FONT_XS, bg=bg,
                     fg=FG_LABEL).pack(side=tk.LEFT, padx=(8, 0))
            _button(row, "✕", lambda pr=p: self._delete_profile(pr),
                    kind="link", font=self.FONT_XS, padx=4, pady=2
                    ).pack(side=tk.RIGHT)
            if is_active:
                tk.Label(row, text=tr("ACTIVE", "АКТИВЕН"),
                         font=("Segoe UI", 8, "bold"), bg=bg,
                         fg=FG_BLUE).pack(side=tk.RIGHT, padx=6)
            else:
                _button(row, tr("Set Active", "Активировать"),
                        lambda pr=p: self._select_profile_settings(pr),
                        font=self.FONT_XS, padx=8, pady=3).pack(side=tk.RIGHT)

        # Кнопки управления.
        manage = tk.Frame(wrap, bg=BG_MAIN)
        manage.pack(fill=tk.X, pady=(10, 0))
        _button(manage, tr("New", "Новый"), self._new_profile,
                kind="primary", font=self.FONT_S, padx=14).pack(side=tk.LEFT)
        _button(manage, tr("Rename", "Переименовать"), self._rename_profile,
                font=self.FONT_S).pack(side=tk.LEFT, padx=6)
        _button(manage, tr("Duplicate", "Дублировать"), self._duplicate_profile,
                font=self.FONT_S).pack(side=tk.LEFT)


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

    def _note(self, parent, text, font=None, fg=FG_DIM, pady=(6, 0)):
        """Мелкая подпись, которая переносится по реальной ширине колонки."""
        label = tk.Label(parent, text=text, font=font or self.FONT_XS,
                         bg=BG_MAIN, fg=fg, justify=tk.LEFT, anchor=tk.W)
        label.pack(anchor=tk.W, pady=pady)
        state = {"width": 0}
        width = parent.winfo_width()
        if width > 1:
            label.configure(wraplength=max(220, width - 8))
            state["width"] = max(220, width - 8)

        def _wrap(event):
            width = max(220, event.width - 8)
            if abs(width - state["width"]) > 4:
                state["width"] = width
                label.configure(wraplength=width)

        parent.bind("<Configure>", _wrap, add="+")
        return label

    def _keep(self, var):
        """Держит ссылку на Tk-переменную.

        Если Python-объект StringVar/BooleanVar соберёт GC, tkinter удалит
        Tcl-переменную и виджет «потеряет» текст/галочку. Поэтому все
        переменные вкладки складываем в список.
        """
        if not hasattr(self, "_vars"):
            self._vars = []
        self._vars.append(var)
        return var

    def _entry(self, parent, textvariable=None, width=None):
        entry = tk.Entry(parent, textvariable=textvariable, font=("Consolas", 9),
                         bg=BG_INPUT, fg=FG_TEXT, insertbackground=FG_TEXT,
                         relief=tk.FLAT, bd=0, highlightthickness=1,
                         highlightbackground=BORDER_SOFT, highlightcolor=BTN_ACCENT,
                         disabledbackground=BG_PANEL, disabledforeground=FG_DIM)
        if width:
            entry.configure(width=width)
        return entry

    def _check(self, parent, text, variable, command=None, bg=BG_MAIN):
        return Check(parent, text, variable, command=command, bg=bg,
                     font=self.FONT_S)

    def _build_connection_tab(self):
        pos = 0.0
        previous = getattr(self, "_conn_scroll", None)
        if previous is not None:
            pos = previous.save_pos()
        self._vars = []
        for w in self.tab_connection.winfo_children():
            w.destroy()

        conn_scroll = ScrollFrame(self.tab_connection, bg=BG_MAIN)
        conn_scroll.pack(fill=tk.BOTH, expand=True)
        inner = conn_scroll.inner
        self._conn_scroll = conn_scroll
        self._conn_inner = inner

        content = tk.Frame(inner, bg=BG_MAIN)
        content.pack(fill=tk.BOTH, expand=True, padx=2, pady=(2, 12))

        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()
        client = cfg["client"]

        # ── Подписка ──
        self._section_label(content, tr("Subscription", "Подписка"), pady=(2, 6))
        sub_row = tk.Frame(content, bg=BG_MAIN)
        sub_row.pack(fill=tk.X)
        self.sub_url_var = tk.StringVar(value=cfg["subscription"].get("url", ""))
        entry = self._entry(sub_row, self.sub_url_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)
        _button(sub_row, tr("Load", "Загрузить"),
                lambda: self._import_subscription_text(self.sub_url_var.get()),
                kind="primary", font=self.FONT_S, padx=14, pady=6
                ).pack(side=tk.LEFT, padx=(8, 0))

        if cfg["user"].get("uuid"):
            tk.Label(content, text=f"{tr('User', 'Пользователь')}: {cfg['user']['uuid']}",
                     font=self.FONT_XS, bg=BG_MAIN, fg=FG_DIM).pack(anchor=tk.W, pady=(4, 0))

        # ── Режим ──
        self._section_label(content, tr("Mode", "Режим"), pady=(18, 6))
        mode_row = tk.Frame(content, bg=BG_MAIN)
        mode_row.pack(fill=tk.X)
        is_vpn = bool(profile and profile["mode"] == "vpn")
        ChipGroup(
            mode_row,
            [("proxy", tr("Proxy (SOCKS5)", "Прокси (SOCKS5)")), ("vpn", "VPN")],
            value=("vpn" if is_vpn else "proxy"),
            command=self._set_mode,
        ).pack(side=tk.LEFT)

        if profile and profile["mode"] == "vpn":
            backend = profile.get("vpn_backend", "tun")
            tun_ok = tun_mode.tun_available()
            tk.Label(content, text=tr("Implementation", "Реализация"),
                     font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL
                     ).pack(anchor=tk.W, pady=(12, 4))
            brow = tk.Frame(content, bg=BG_MAIN)
            brow.pack(fill=tk.X)
            backend_group = ChipGroup(
                brow,
                [("tun", tr("TUN (all traffic)", "TUN (весь трафик)")),
                 ("system", tr("System proxy", "Системный прокси"))],
                value=("system" if backend == "system" else "tun"),
                command=self._set_vpn_backend,
            )
            backend_group.pack(side=tk.LEFT)
            backend_group.set_enabled("tun", tun_ok)

            if backend == "tun":
                note = (tr("TUN mode creates a Wintun adapter and routes all traffic. "
                           "Windows asks for administrator rights once per app launch.",
                           "TUN-режим создаёт Wintun-адаптер и заворачивает весь трафик. "
                           "Windows попросит права администратора один раз за запуск.")
                        if tun_ok else
                        tr("TUN backend is unavailable: bin/win/tun2proxy-bin.exe or wintun.dll not found.",
                           "TUN-бэкенд недоступен: не найден bin/win/tun2proxy-bin.exe или wintun.dll."))
            else:
                note = tr("System proxy mode configures the Windows proxy; apps that ignore it bypass the VPN.",
                          "Режим системного прокси настраивает прокси Windows; приложения, "
                          "игнорирующие его, идут мимо VPN.")
            self._note(content, note, pady=(6, 0))

        # ── Маршрутизация ──
        self._section_label(content, tr("Routing", "Маршрутизация"), pady=(18, 6))
        routing = cfg["routing"]
        rrow = tk.Frame(content, bg=BG_MAIN)
        rrow.pack(fill=tk.X)
        self.routing_var = tk.BooleanVar(value=bool(routing.get("enabled")))
        self._check(rrow, tr("Split routing", "Раздельная маршрутизация"),
                    self.routing_var, self._on_routing_toggle).pack(side=tk.LEFT)

        route_names = [r for r in (cfg.get("routing_options") or "").split("|") if r]
        options = route_names + ["direct"]
        if self.routing_var.get():
            if not route_names:
                tk.Label(content,
                         text=tr("Load a subscription to get route names.",
                                 "Загрузите подписку, чтобы получить названия маршрутов."),
                         font=self.FONT_XS, bg=BG_MAIN, fg=FG_DIM
                         ).pack(anchor=tk.W, pady=(4, 0))
            self._route_selector(content, "RU", "ru", routing.get("ru", ""), options)
            self._route_selector(content, tr("non-RU", "не-RU"), "non_ru",
                                 routing.get("non_ru", ""), options)
            self._route_selector(content, tr("Private / LAN", "Локальная сеть"),
                                 "private", routing.get("private", "direct"), options)

        # ── Серверные URL ──
        self._section_label(content, tr("Server URLs", "Серверные URL"), pady=(18, 6))
        self._server_url_vars = []
        for i, url in enumerate(client.get("server_urls") or []):
            row = tk.Frame(content, bg=BG_MAIN)
            row.pack(fill=tk.X, pady=2)
            enabled_var = tk.BooleanVar(
                value=url.rstrip("/") not in
                {u.rstrip("/") for u in client.get("disabled_urls", [])})
            self._check(row, "", enabled_var,
                        lambda u=url, v=enabled_var: self._toggle_url(u, v.get())
                        ).pack(side=tk.LEFT)
            var = self._keep(tk.StringVar(value=url))
            self._server_url_vars.append((var, enabled_var))
            entry = self._entry(row, var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4, padx=6)
            entry.bind("<FocusOut>",
                       lambda _e, idx=i, v=var: self._save_server_url(idx, v.get()))
            entry.bind("<Return>",
                       lambda _e, idx=i, v=var: self._save_server_url(idx, v.get()))
            _button(row, "✕", lambda idx=i: self._remove_url(idx),
                    kind="link", font=self.FONT_S, padx=5, pady=2).pack(side=tk.LEFT)

        _button(content, tr("+ Add URL", "+ Добавить URL"), self._add_url,
                font=self.FONT_S, padx=10, pady=5).pack(anchor=tk.W, pady=6)

        # ── Статус URL ──
        self.url_status_frame = tk.Frame(content, bg=BG_PANEL,
                                         highlightbackground=BORDER_SOFT,
                                         highlightthickness=1)
        self.url_status_frame.pack(fill=tk.X, pady=6)
        self._url_status_sig = None
        self._url_rows = []
        self._build_url_status()

        # ── Параметры ──
        self._build_advanced_fields(content, client)

        if pos:
            try:
                self.root.after_idle(lambda: conn_scroll.canvas.yview_moveto(pos))
            except tk.TclError:
                pass


    def _build_advanced_fields(self, parent, client: dict):
        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()

        def field(label, value, key, cast=lambda v: v):
            row = tk.Frame(parent, bg=BG_MAIN)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL,
                     width=24, anchor=tk.W).pack(side=tk.LEFT)
            var = self._keep(tk.StringVar(value=str(value)))

            def save(*_):
                try:
                    self._set_client_value(key, cast(var.get()))
                except Exception:
                    pass

            entry = self._entry(row, var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
            entry.bind("<FocusOut>", save)
            entry.bind("<Return>", save)
            return var

        self._section_label(parent, tr("Advanced", "Дополнительно"), pady=(18, 6))
        field(tr("Poll interval (ms)", "Интервал опроса (мс)"),
              client.get("poll_interval_ms", 200), "poll_interval_ms", int)
        field(tr("Max chunk", "Макс. чанк"), client.get("max_chunk_bytes", 65536),
              "max_chunk_bytes", int)
        field(tr("Poll path", "Путь опроса"), client.get("poll_path", "/poll"),
              "poll_path", str)
        field(tr("Host header", "Host-заголовок"), client.get("host_header", ""),
              "host_header", str)
        field(tr("SOCKS port", "Порт SOCKS"), client["socks5"].get("bind_port", 8888),
              "socks_port", int)
        field(tr("HTTP port", "Порт HTTP"), client["socks5"].get("http_port", 8889),
              "http_port", int)
        field(tr("Quarantine (s)", "Карантин (с)"),
              client.get("url_cooldown_seconds", 60), "url_cooldown_seconds", int)
        field(tr("Fail limit", "Лимит ошибок"), client.get("url_fail_limit", 3),
              "url_fail_limit", int)

        pad_row = tk.Frame(parent, bg=BG_MAIN)
        pad_row.pack(fill=tk.X, pady=4)
        pad_var = self._keep(tk.BooleanVar(value=bool(client.get("pad_polls", True))))
        self._check(
            pad_row, tr("Pad poll sizes", "Маскировать размеры poll"), pad_var,
            lambda: self._set_client_value("pad_polls", pad_var.get())
        ).pack(side=tk.LEFT)

        method_row = tk.Frame(parent, bg=BG_MAIN)
        method_row.pack(fill=tk.X, pady=4)
        tk.Label(method_row, text=tr("Poll method", "Метод опроса"),
                 font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL, width=24,
                 anchor=tk.W).pack(side=tk.LEFT)
        method = str(client.get("poll_method") or "POST").upper()
        ChipGroup(
            method_row,
            [("GET", "GET"), ("POST", "POST")],
            value=("GET" if method == "GET" else "POST"),
            command=lambda value: self._set_client_value("poll_method", value),
        ).pack(side=tk.LEFT)

        data_row = tk.Frame(parent, bg=BG_MAIN)
        data_row.pack(fill=tk.X, pady=4)
        tk.Label(data_row, text=tr("Data in", "Данные в"),
                 font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL, width=24,
                 anchor=tk.W).pack(side=tk.LEFT)
        data_in = str(client.get("poll_data_in") or "body").lower()
        ChipGroup(
            data_row,
            [("body", "body"), ("header", "header")],
            value=("header" if data_in == "header" else "body"),
            command=lambda value: self._set_client_value("poll_data_in", value),
        ).pack(side=tk.LEFT)

        tls_row = tk.Frame(parent, bg=BG_MAIN)
        tls_row.pack(fill=tk.X, pady=4)
        tls_var = self._keep(tk.BooleanVar(value=bool(client.get("verify_tls", True))))
        self._check(
            tls_row, tr("Verify TLS certificate", "Проверять TLS-сертификат"),
            tls_var, lambda: self._set_client_value("verify_tls", tls_var.get())
        ).pack(side=tk.LEFT)

        self._build_tun_fields(parent, client)

        # Продвинутый JSON.
        self._divider(parent, pady=(18, 10))
        self._section_label(parent, tr("Advanced config (JSON)",
                                       "Продвинутый конфиг (JSON)"), pady=(0, 6))
        self._note(parent, tr("Server block is ignored; only client and security sections matter.",
                              "Блок server игнорируется; важны только client и security."),
                   pady=0)
        self.raw_editor = tk.Text(
            parent, height=12, font=("Consolas", 9), bg=BG_LOG, fg=FG_TEXT,
            insertbackground=FG_TEXT, relief=tk.FLAT, wrap=tk.NONE, bd=0,
            highlightthickness=1, highlightbackground=BORDER_SOFT,
            highlightcolor=BTN_ACCENT)
        self.raw_editor.pack(fill=tk.X, pady=4)
        self.raw_editor.insert("1.0", json.dumps(cfg, ensure_ascii=False, indent=2))
        _button(parent, tr("Save config", "Сохранить конфиг"), self._save_raw_config,
                kind="primary", font=self.FONT_S, padx=14, pady=6
                ).pack(anchor=tk.W, pady=(4, 8))

    def _build_tun_fields(self, parent, client: dict):
        """TUN-параметры, DNS-relay и idle-timeout."""
        self._section_label(parent, tr("TUN / idle", "TUN / простой"), pady=(18, 6))

        tun = client.get("tun") or {}
        tun_exe = tun_mode.tun2proxy_path()
        self._note(parent,
                   tr("tun2proxy: ", "tun2proxy: ") + (str(tun_exe) if tun_exe else
                   tr("not found (bin/win)", "не найден (bin/win)")),
                   font=("Consolas", 8), pady=0)

        def tun_field(label, value, key, cast=lambda v: v):
            row = tk.Frame(parent, bg=BG_MAIN)
            row.pack(fill=tk.X, pady=2)
            tk.Label(row, text=label, font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL,
                     width=24, anchor=tk.W).pack(side=tk.LEFT)
            var = self._keep(tk.StringVar(value=str(value)))

            def save(*_):
                try:
                    self._set_tun_value(key, cast(var.get()))
                except Exception:
                    pass

            entry = self._entry(row, var)
            entry.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=4)
            entry.bind("<FocusOut>", save)
            entry.bind("<Return>", save)

        tun_field(tr("TUN MTU", "MTU TUN"), tun.get("mtu", 1500), "mtu", int)
        tun_field(tr("Adapter name", "Имя адаптера"), tun.get("name", "vpnclient"),
                  "name", str)
        tun_field(tr("Helper port", "Порт помощника"), tun.get("helper_port", 41417),
                  "helper_port", int)
        tun_field(tr("Bypass IPs (comma)", "Bypass IP (через запятую)"),
                  ",".join(tun.get("bypass_ips") or []), "bypass_ips", str)

        hij_row = tk.Frame(parent, bg=BG_MAIN)
        hij_row.pack(fill=tk.X, pady=3)
        hij_var = self._keep(tk.BooleanVar(value=bool(tun.get("dns_hijack", True))))
        self._check(
            hij_row,
            tr("Route system DNS through the tunnel (no leaks)",
               "Завернуть системный DNS в туннель (без утечек)"),
            hij_var, lambda: self._set_tun_value("dns_hijack", hij_var.get())
        ).pack(side=tk.LEFT)

        dns_row = tk.Frame(parent, bg=BG_MAIN)
        dns_row.pack(fill=tk.X, pady=4)
        tk.Label(dns_row, text=tr("TUN DNS", "DNS в TUN"), font=self.FONT_XS,
                 bg=BG_MAIN, fg=FG_LABEL, width=24,
                 anchor=tk.W).pack(side=tk.LEFT)
        ChipGroup(
            dns_row,
            [("virtual", "virtual"), ("over-tcp", "over-tcp"), ("direct", "direct")],
            value=(tun.get("dns_mode") or "virtual"),
            command=lambda value: self._set_tun_value("dns_mode", value),
        ).pack(side=tk.LEFT)

        idle = client.get("idle_timeout") or {}
        idle_row = tk.Frame(parent, bg=BG_MAIN)
        idle_row.pack(fill=tk.X, pady=4)
        idle_var = self._keep(tk.BooleanVar(value=bool(idle.get("enabled"))))
        idle_secs = self._keep(tk.StringVar(value=str(idle.get("seconds", 300))))

        def save_idle(*_):
            try:
                self._set_client_value("idle_timeout", {
                    "enabled": idle_var.get(), "seconds": int(idle_secs.get())})
            except Exception:
                pass

        self._check(
            idle_row, tr("Idle timeout", "Таймаут простоя"), idle_var,
            lambda: (self._set_client_value(
                "idle_timeout", {"enabled": idle_var.get(),
                                 "seconds": int(idle.get("seconds", 300))}))
        ).pack(side=tk.LEFT)
        idle_entry = self._entry(idle_row, idle_secs, width=7)
        idle_entry.pack(side=tk.LEFT, padx=(8, 0), ipady=3)
        idle_entry.bind("<FocusOut>", save_idle)
        idle_entry.bind("<Return>", save_idle)
        tk.Label(idle_row, text=tr("sec", "с"), font=self.FONT_XS, bg=BG_MAIN,
                 fg=FG_DIM).pack(side=tk.LEFT, padx=4)

        dns_relay = client.get("dns_relay") or {}
        dr_row = tk.Frame(parent, bg=BG_MAIN)
        dr_row.pack(fill=tk.X, pady=(4, 8))
        dr_var = self._keep(tk.BooleanVar(value=bool(dns_relay.get("enabled"))))
        self._check(
            dr_row, tr("DNS relay on port 5353", "DNS-релей на порту 5353"),
            dr_var, lambda: self._set_client_value("dns_relay", {
                "enabled": dr_var.get(),
                "bind_host": dns_relay.get("bind_host", "127.0.0.1"),
                "bind_port": int(dns_relay.get("bind_port", 5353))})
        ).pack(side=tk.LEFT)


    # ── Настройки профиля ──

    def _current_profile(self) -> Optional[dict]:
        return self.cfg.get_active_profile()

    def _mutate_profile(self, fn, refresh: bool = True):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        new_config = fn(profile["config"])
        if new_config is None:
            return
        profile["config"] = new_config
        self.cfg.update_profile(profile)
        if refresh:
            self._refresh_profiles()

    def _set_mode(self, mode: str):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        profile["mode"] = mode
        self.cfg.update_profile(profile)
        self._build_connection_tab()
        self._refresh_profiles()

    def _set_vpn_backend(self, backend: str):
        profile = self.cfg.get_active_profile()
        if not profile:
            return
        profile["vpn_backend"] = "system" if backend == "system" else "tun"
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
        # GET/POST, body/header и прочие поля не меняют главный экран —
        # не перестраиваем его и не сбрасываем прокрутку настроек.
        self._mutate_profile(fn, refresh=False)
        if key in ("socks_port", "http_port"):
            self._reload_display_config()
            self._update_idle_info()

    def _set_tun_value(self, key: str, value):
        def fn(cfg):
            tun = cfg["client"].setdefault("tun", {})
            if key == "bypass_ips":
                items = [s.strip() for s in str(value).split(",") if s.strip()]
                tun["bypass_ips"] = items
            else:
                tun[key] = value
            return cfg
        self._mutate_profile(fn, refresh=False)

    def _on_routing_toggle(self):
        enabled = self.routing_var.get()

        def fn(cfg):
            cfg["routing"]["enabled"] = enabled
            return cfg

        self._mutate_profile(fn)
        self._build_connection_tab()

    def _route_selector(self, parent, label: str, key: str, value: str, options: list[str]):
        """Маршрут выбирается из выпадающего списка — длинные списки не обрезаются."""
        row = tk.Frame(parent, bg=BG_MAIN)
        row.pack(fill=tk.X, pady=3)
        tk.Label(row, text=label, font=self.FONT_XS, bg=BG_MAIN, fg=FG_LABEL,
                 width=16, anchor=tk.W).pack(side=tk.LEFT)

        options = list(options)
        current = (value or "").strip()
        if current and current not in options:
            options.insert(0, current)
        display = ["Direct" if opt == "direct" else opt for opt in options]
        initial = "Direct" if current == "direct" else current
        if not initial and display:
            initial = display[0]
        var = self._keep(tk.StringVar(value=initial))
        combo = ttk.Combobox(row, textvariable=var, values=display,
                             state="readonly", font=self.FONT_S,
                             height=min(18, max(6, len(display))))
        combo.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(6, 0))

        def apply(_e=None):
            idx = combo.current()
            if 0 <= idx < len(options):
                self._set_route(key, options[idx])

        combo.bind("<<ComboboxSelected>>", apply)
        return combo

    def _set_route(self, key: str, route: str):
        def fn(cfg):
            cfg["routing"][key] = route
            return cfg

        # Значение уже подсвечено в Combobox — перестройка вкладки не нужна.
        self._mutate_profile(fn, refresh=False)

    def _toggle_url(self, url: str, enabled: bool):
        normalized = url.rstrip("/")

        def fn(cfg):
            disabled = list(cfg["client"].get("disabled_urls") or [])
            disabled = [u for u in disabled if u.rstrip("/") != normalized]
            if not enabled:
                disabled.append(normalized)
            cfg["client"]["disabled_urls"] = disabled
            return cfg

        self._mutate_profile(fn, refresh=False)
        self._build_url_status()
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

        self._mutate_profile(fn, refresh=False)
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

        self._mutate_profile(fn, refresh=False)
        self._build_url_status()

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

        self._mutate_profile(fn, refresh=False)
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
        frame = getattr(self, "url_status_frame", None)
        if frame is None or not frame.winfo_exists():
            return

        profile = self.cfg.get_active_profile()
        cfg = profile["config"] if profile else default_profile_config()
        urls = [u for u in (cfg["client"].get("server_urls") or []) if u]

        signature = tuple(urls)
        if self._url_status_sig != signature:
            self._url_status_sig = signature
            self._url_rows = []
            for w in frame.winfo_children():
                w.destroy()

            head = tk.Frame(frame, bg=BG_PANEL)
            head.pack(fill=tk.X, padx=12, pady=(10, 4))
            tk.Label(head, text=tr("URL status", "Статус URL").upper(),
                     font=("Segoe UI", 8, "bold"), bg=BG_PANEL,
                     fg=FG_DIM).pack(side=tk.LEFT)
            _button(head, tr("Reset errors", "Сбросить ошибки"),
                    self._reset_url_errors, kind="link", font=self.FONT_XS,
                    padx=2, pady=0).pack(side=tk.RIGHT)

            if not urls:
                tk.Label(frame, text=tr("No server URLs configured",
                                        "URL серверов не настроены"),
                         font=self.FONT_XS, bg=BG_PANEL,
                         fg=FG_LABEL).pack(anchor=tk.W, padx=12, pady=4)

            for url in urls:
                row = tk.Frame(frame, bg=BG_PANEL)
                row.pack(fill=tk.X, padx=12, pady=1)
                dot = tk.Label(row, text="\u25cf", font=("Segoe UI", 7),
                               bg=BG_PANEL, fg=FG_GREEN)
                dot.pack(side=tk.LEFT, padx=(0, 6))
                tk.Label(row, text=url, font=("Consolas", 8), bg=BG_PANEL,
                         fg=FG_TEXT, anchor=tk.W).pack(side=tk.LEFT)
                state = tk.Label(row, text="", font=("Segoe UI", 8),
                                 bg=BG_PANEL, fg=FG_LABEL)
                state.pack(side=tk.RIGHT)
                self._url_rows.append({"url": url, "dot": dot, "state": state})

            self._url_note = tk.Label(
                frame,
                text=(tr("URL changes and quarantine time apply after reconnect.",
                         "Изменения URL и карантин применяются после переподключения.")
                      if self.running else
                      tr("Connect to see live quarantine state.",
                         "Подключитесь, чтобы увидеть живой статус карантина.")),
                font=("Segoe UI", 8), bg=BG_PANEL, fg=FG_DIM, wraplength=520,
                justify=tk.LEFT)
            self._url_note.pack(anchor=tk.W, padx=12, pady=(4, 10))

        disabled_urls = {u.rstrip("/") for u in cfg["client"].get("disabled_urls", [])}
        for item in self._url_rows:
            url = item["url"]
            runtime = self._last_url_status.get(url.rstrip("/"))
            disabled = url.rstrip("/") in disabled_urls
            if self.running and runtime is not None:
                disabled = not runtime.get("enabled", True)
            if disabled:
                label, color = tr("Disabled", "Отключён"), FG_LABEL
            elif runtime and runtime.get("quarantined"):
                label = (tr("Quarantine", "Карантин")
                         + f" · {runtime.get('cooldown_remaining', 0)}s")
                color = FG_AMBER
            elif runtime and runtime.get("errors", 0) > 0:
                label = (tr("Active", "Активен") + f" · {runtime['errors']} "
                         + tr("error(s)", "ошиб."))
                color = FG_RED
            else:
                label, color = tr("Active", "Активен"), FG_GREEN
            self._set_text(item["dot"], "\u25cf", color)
            self._set_text(item["state"], label, color)

        note = getattr(self, "_url_note", None)
        if note is not None and note.winfo_exists():
            self._set_text(
                note,
                tr("URL changes and quarantine time apply after reconnect.",
                   "Изменения URL и карантин применяются после переподключения.")
                if self.running else
                tr("Connect to see live quarantine state.",
                   "Подключитесь, чтобы увидеть живой статус карантина."))

    def _reset_url_errors(self):
        if self._tunnel and self._loop:
            self._loop.call_soon_threadsafe(self._tunnel.reset_url_status)
            self._log(tr("URL error counters reset", "Счётчики ошибок URL сброшены"), "INFO")

    def _build_logs_tab(self):
        for w in self.tab_logs.winfo_children():
            w.destroy()

        wrap = tk.Frame(self.tab_logs, bg=BG_MAIN)
        wrap.pack(fill=tk.BOTH, expand=True, padx=2)

        log_wrap, self.settings_log = self._make_log_text(wrap)
        log_wrap.configure(highlightthickness=1, highlightbackground=BORDER_SOFT)
        log_wrap.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        for tag, color in (("INFO", FG_TEXT), ("WARNING", FG_AMBER),
                            ("ERROR", FG_RED), ("DEBUG", FG_DIM)):
            self.settings_log.tag_config(tag, foreground=color)

        # Копируем текущее содержимое главного лога.
        try:
            content = self.log_text.get("1.0", tk.END)
            self.settings_log.configure(state="normal")
            self.settings_log.insert("1.0", content)
            self.settings_log.configure(state="disabled")
        except Exception:
            pass

        row = tk.Frame(wrap, bg=BG_MAIN)
        row.pack(fill=tk.X)
        _button(row, tr("Copy all", "Копировать всё"), self._copy_logs,
                font=self.FONT_S).pack(side=tk.LEFT)
        _button(row, tr("Clear", "Очистить"), self._clear_logs,
                font=self.FONT_S).pack(side=tk.LEFT, padx=6)

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
        icon_image = self._create_tray_image(False)
        menu = pystray.Menu(
            pystray.MenuItem("Show", self._tray_show, default=True),
            pystray.MenuItem("Quit", self._tray_quit),
        )
        self._tray = pystray.Icon("VPN", icon_image, "Short Polling VPN", menu)
        self._tray_thread = threading.Thread(target=self._tray.run, daemon=True)
        self._tray_thread.start()

    def _start_instance_server(self):
        """Ловит повторный запуск: второй экземпляр просит показать окно."""
        self._instance_sock = None
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind(("127.0.0.1", INSTANCE_PORT))
            srv.listen(4)
            srv.settimeout(0.5)
        except OSError:
            return
        self._instance_sock = srv

        def worker():
            while self._instance_sock is not None:
                try:
                    conn, _addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                try:
                    conn.settimeout(1.0)
                    if b"show" in conn.recv(32):
                        self._post(self._show_window)
                        try:
                            conn.sendall(b"ok\n")
                        except OSError:
                            pass
                except OSError:
                    pass
                finally:
                    try:
                        conn.close()
                    except OSError:
                        pass

        threading.Thread(target=worker, daemon=True).start()

    def _stop_instance_server(self):
        srv = getattr(self, "_instance_sock", None)
        self._instance_sock = None
        if srv is not None:
            try:
                srv.close()
            except OSError:
                pass

    def _create_tray_image(self, connected: bool = False):
        img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([1, 1, 14, 14], fill="#252536", outline="#a6e3a1")
        draw.rectangle([4, 4, 11, 11],
                       fill=("#a6e3a1" if connected else "#6c7086"))
        return img

    def _refresh_tray_icon(self):
        tray = getattr(self, "_tray", None)
        if tray is None:
            return
        try:
            tray.icon = self._create_tray_image(self.running)
            tray.title = ("Short Polling VPN — connected" if self.running
                          else "Short Polling VPN")
        except Exception:
            pass

    def _tray_show(self, icon=None, item=None):
        self._post(self._show_window)

    def _show_window(self):
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_quit(self, icon=None, item=None):
        self._post(self._quit_app)

    def _on_hide(self):
        self.root.withdraw()
        try:
            self._tray.notify(
                tr("VPN keeps running in the tray. Click the icon to reopen.",
                   "VPN продолжает работать в трее. Нажмите на значок, чтобы открыть окно."),
                tr("Minimized to tray", "Свёрнуто в трей"))
        except Exception:
            pass

    # ══════════════════════════════════════════════════════════════════
    #  Запуск / Остановка
    # ══════════════════════════════════════════════════════════════════

    def _on_toggle(self):
        if self._stopping:
            return
        if self.running:
            self._stop()
        else:
            self._start()

    def _foreign_default_route(self) -> Optional[dict]:
        """Чужой VPN, уже занявший default-route (None — маршрут свободен)."""
        if not self._use_tun():
            return None
        tun_cfg = (((self.engine_cfg or {}).get("client") or {}).get("tun")) or {}
        own = ["vpnclient"]
        name = str(tun_cfg.get("name") or "").strip()
        if name:
            own.append(name)
        try:
            return tun_mode.foreign_tunnel_route(own)
        except Exception as exc:
            self._log(f"route pre-check failed: {exc}", "DEBUG")
            return None

    def _start(self):
        if self._stopping:
            return
        self._reload_display_config()
        if not self.active_profile:
            messagebox.showwarning(tr("No profile", "Нет профиля"),
                                   tr("Add a subscription or create a profile first.",
                                      "Сначала добавьте подписку или создайте профиль."))
            return

        self._set_text(self.hero_hint, tr("Checking route…", "Проверка маршрута…"),
                       FG_AMBER)
        try:
            self.root.update_idletasks()
        except Exception:
            pass
        foreign = self._foreign_default_route()
        if foreign:
            self._tun_route_busy = True
            name = str(foreign.get("alias") or "?")
            self._log(tr(f"Another VPN holds the default route: {name}. "
                         "Disable it, otherwise traffic will not go through this VPN.",
                         f"Default-route занят другим VPN: {name}. Отключите его, "
                         "иначе трафик не пойдёт через этот VPN."), "WARNING")
            self._set_text(
                self.hero_hint,
                tr(f"Route is taken by {name} — disable that VPN",
                   f"Маршрут занят: {name} — отключите этот VPN"), FG_AMBER)
            if _dialogs_allowed():
                messagebox.showwarning(
                    tr("Another VPN is active", "Другой VPN уже включён"),
                    tr(f"The default route is held by “{name}” "
                       f"({foreign.get('desc') or 'virtual adapter'}).\n\n"
                       "While it runs, traffic will not go through this VPN.\n"
                       "Disable it and connect again.",
                       f"Маршрут по умолчанию держит «{name}» "
                       f"({foreign.get('desc') or 'виртуальный адаптер'}).\n\n"
                       "Пока он включён, трафик не пойдёт через этот VPN.\n"
                       "Отключите его и подключитесь снова."))
            return

        self._tun_route_busy = False
        self.running = True
        self.start_btn.configure(text=tr("Disconnect", "Отключить"), on=True)
        self._update_status(True)
        self._set_text(self.hero_hint, tr("Connecting…", "Подключение…"), FG_AMBER)
        self._set_text(self.info_label, tr("Connecting...", "Подключение..."))
        self._set_text(self.proxy_indicator, "", FG_LABEL)
        self._log("VPN starting...", "INFO")

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        self.root.after(1500, self._check_started)
        self._schedule_proxy_guard()
        self._schedule_url_status()
        self._start_config_watcher()

    def _vpn_backend(self) -> str:
        if not self.active_profile or self.active_profile["mode"] != "vpn":
            return ""
        return self.active_profile.get("vpn_backend", "tun")

    def _use_tun(self) -> bool:
        return self._vpn_backend() == "tun"

    def _use_system_proxy(self) -> bool:
        """Нужно ли заворачивать системный прокси Windows на наш HTTP-порт.

        Режим Proxy — это готовый SOCKS5/HTTP на localhost; без системного
        прокси обычные приложения (браузер, Electron) в него не ходят, и
        режим выглядел «включённым, но неработающим».
        """
        if not self.active_profile or sys.platform != "win32":
            return False
        if self.socks_host not in ("0.0.0.0", "127.0.0.1", "localhost"):
            return False
        return (self.active_profile.get("mode") == "proxy"
                or self._vpn_backend() == "system")

    def _apply_system_proxy(self) -> None:
        with self._proxy_lock:
            if self._proxy_applied:
                return
            if not self._proxy_snapshot:
                self._proxy_snapshot = get_system_proxy_windows()
            set_system_proxy_windows("127.0.0.1", self.socks_port,
                                     self.http_port, True)
            self._proxy_applied = True
        self._log(f"System proxy → 127.0.0.1:{self.http_port}", "INFO")

    def _restore_system_proxy(self) -> None:
        with self._proxy_lock:
            if not self._proxy_applied:
                return
            snapshot, self._proxy_snapshot = self._proxy_snapshot, {}
            self._proxy_applied = False
        if snapshot:
            restore_system_proxy_windows(snapshot)
            self._log("System proxy restored to previous settings.", "INFO")
        else:
            set_system_proxy_windows("127.0.0.1", self.socks_port,
                                     self.http_port, False)
            self._log("System proxy cleared.", "INFO")

    def _schedule_proxy_guard(self):
        if not self.running:
            return
        # В TUN-режиме системный прокси не нужен (и вреден: двойной обход).
        if self._use_system_proxy():
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    needs_fix = (not enabled or "127.0.0.1" not in server
                                 or str(self.http_port) not in server)
                if needs_fix or not self._proxy_applied:
                    self._log("Proxy was overwritten — re-setting", "WARNING")
                    with self._proxy_lock:
                        self._proxy_applied = False
                    self._apply_system_proxy()
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
        self.root.after(2000, self._schedule_url_status)

    def _start_config_watcher(self):
        self._stop_config_watcher()
        if not os.path.exists(self.config_path):
            return
        handler = ConfigFileHandler(self.config_path, self._post, self._on_config_changed)
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
        # Порт и режим показываются в info-bar; лог не засоряем на каждый refresh.
        pass

    def _check_started(self):
        hint = None
        hint_color = FG_DIM
        if self.running and self._tunnel:
            if self._use_tun():
                if self._tun_active and self._tun_route_busy:
                    label, color = tr("TUN: ROUTE BUSY", "TUN: МАРШРУТ ЗАНЯТ"), FG_AMBER
                elif self._tun_active:
                    label, color = tr("TUN: UP", "TUN: АКТИВЕН"), FG_GREEN
                    hint = tr("Connected · traffic is encrypted",
                              "Подключено · трафик зашифрован")
                    hint_color = FG_GREEN
                elif self._tun_error:
                    label, color = tr("TUN: ERROR", "TUN: ОШИБКА"), FG_RED
                    hint = tr(f"TUN error: {self._tun_error}",
                              f"Ошибка TUN: {self._tun_error}")
                    hint_color = FG_RED
                else:
                    label, color = tr("TUN: starting…", "TUN: запуск…"), FG_AMBER
                    hint = tr("Starting tunnel…", "Запуск туннеля…")
                    hint_color = FG_AMBER
                self._set_text(
                    self.info_label,
                    f"SOCKS {self.socks_port}   ·   HTTP {self.http_port}   ·   {label}")
                self._set_text(self.proxy_indicator, label, color)
            else:
                proxy_status = self._verify_system_proxy()
                http_addr = f"127.0.0.1:{self.http_port}"
                self._set_text(
                    self.info_label,
                    f"SOCKS {self.socks_host}:{self.socks_port}   ·   "
                    f"HTTP {http_addr}   ·   PROXY {proxy_status}")
                self._set_text(self.proxy_indicator, f"PROXY: {proxy_status}",
                               FG_GREEN if proxy_status == "SET" else FG_RED)
                if proxy_status == "SET":
                    hint = tr(f"Connected · system proxy {http_addr}",
                              f"Подключено · системный прокси {http_addr}")
                    hint_color = FG_GREEN
                else:
                    hint = tr(f"Proxy is not applied — check {http_addr}",
                              f"Прокси не применён — проверьте {http_addr}")
                    hint_color = FG_AMBER
        if hint:
            if len(hint) > 70:
                hint = hint[:67] + "…"
            self._set_text(self.hero_hint, hint, hint_color)
        if self.running:
            self.root.after(2000, self._check_started)

    # ── TUN-режим ──

    def _start_tun(self):
        """Поднимает Wintun через elevated-помощник (в отдельном потоке)."""
        threading.Thread(target=self._start_tun_worker, daemon=True).start()

    def _start_tun_worker(self):
        profile = self.active_profile or {}
        client = (profile.get("config") or {}).get("client") or {}
        tun_cfg = client.get("tun") or {}
        port = int(tun_cfg.get("helper_port", tun_mode.DEFAULT_HELPER_PORT))
        token = self.cfg.get_pref("tun_helper_token", "") or os.urandom(16).hex()
        self.cfg.set_pref("tun_helper_token", token)

        bypass = list(tun_cfg.get("bypass_ips") or [])
        # IP узлов: берём уже разрезолвленную карту туннеля и литеральные IP.
        # Повторный getaddrinfo здесь опасен — DNS мог быть уже переключён
        # на TUN, и мы получили бы fake-IP.
        resolved = tuple((self._tunnel._host_ip or {}).values()) if self._tunnel else ()
        for ip in list(resolved) + tun_mode.literal_ips_from_urls(self.server_urls):
            if ip and ip not in bypass:
                bypass.append(ip)

        helper = self._tun_helper
        if helper is None or not helper.matches(port, token):
            # Порт/токен сменились — старый помощник больше не нужен.
            if helper is not None:
                try:
                    helper.quit()
                except Exception:
                    pass
            helper = tun_mode.TunHelperClient(
                on_log=lambda m: self._log(m, "INFO"))
            self._tun_helper = helper
        try:
            if not helper.connect(port, token):
                self._tun_error = "helper"
                self._log(tr("TUN: elevated helper unavailable (UAC declined?)",
                             "TUN: повышенный помощник недоступен (UAC отклонён?)"), "ERROR")
                return
            resp = helper.start_tun(
                "127.0.0.1", self.socks_port,
                mtu=int(tun_cfg.get("mtu", 1500)),
                dns_mode=str(tun_cfg.get("dns_mode", tun_mode.DEFAULT_DNS_MODE)),
                bypass_ips=bypass,
                verbosity=str(tun_cfg.get("verbosity", "info")),
                tun_name=str(tun_cfg.get("name") or ""),
                dns_hijack=bool(tun_cfg.get("dns_hijack", True)),
                physical_alias=str((self._phys_adapter or {}).get("alias") or ""),
                physical_ip=str((self._phys_adapter or {}).get("ip") or ""),
            )
            if not resp.get("ok"):
                self._tun_error = str(resp.get("error") or "start failed")
                self._log(f"TUN start failed: {self._tun_error}", "ERROR")
                return
            self._tun_active = True
            self._tun_error = ""
            self._log(tr("TUN adapter is up: all traffic goes through the VPN.",
                         "TUN-адаптер поднят: весь трафик идёт через VPN."), "INFO")
            threading.Thread(target=self._verify_tun_route,
                             args=(str(tun_cfg.get("name") or "vpnclient"),),
                             daemon=True).start()
        except Exception as exc:
            self._tun_error = f"{type(exc).__name__}: {exc}"
            self._log(f"TUN error: {self._tun_error}", "ERROR")

    def _verify_tun_route(self, tun_name: str) -> None:
        """Предупреждает, если default-route захвачен другим VPN."""
        time.sleep(4.0)
        if not self._tun_active:
            return
        alias = tun_mode.default_route_alias()
        if alias and tun_name and alias.lower() != tun_name.lower():
            self._tun_route_busy = True
            self._log(tr(f"TUN: default route is on '{alias}' — another VPN "
                         "captures traffic; disable it for full tunneling.",
                         f"TUN: default-route на '{alias}' — трафик перехватывает "
                         "другой VPN; отключите его, чтобы весь трафик шёл сюда."),
                      "WARNING")
        else:
            self._tun_route_busy = False

    def _stop_tun(self):
        helper = self._tun_helper
        self._tun_active = False
        self._tun_error = ""
        self._tun_route_busy = False
        if helper is None:
            return
        try:
            helper.stop_tun()
        except Exception as exc:
            self._log(f"TUN stop error: {exc}", "WARNING")
        # Помощник и его соединение переиспользуются между подключениями:
        # так повторный Connect не требует нового UAC, а закрытие приложения
        # (/quit) гасит его окончательно.

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
        if self._stopping:
            return
        self._stopping = True
        self.running = False
        self._update_status(False)
        self._set_text(self.info_label, tr("Disconnecting...", "Отключение..."))
        self._set_text(self.proxy_indicator, "", FG_LABEL)
        self._set_text(self.hero_hint, tr("Disconnecting…", "Отключение…"), FG_AMBER)
        self._log("VPN stopping...", "INFO")
        self.start_btn.configure(text=tr("Disconnecting…", "Отключение…"),
                                 on=True, state=tk.DISABLED)
        threading.Thread(target=self._stop_worker, daemon=True).start()

    def _teardown(self, join_timeout: float = 12.0) -> None:
        """Блокирующая остановка: TUN, системный прокси, loop, поток."""
        try:
            self._stop_tun()
        except Exception as exc:
            self._log(f"TUN stop failed: {exc}", "WARNING")
        try:
            self._restore_system_proxy()
        except Exception as exc:
            self._log(f"System proxy restore failed: {exc}", "WARNING")
        loop = self._loop
        if loop is not None and loop.is_running():
            try:
                loop.call_soon_threadsafe(loop.stop)
            except Exception:
                pass
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=join_timeout)
        self._loop = None
        self._thread = None
        self._tunnel = None

    def _stop_worker(self):
        try:
            self._teardown()
            self._last_url_status = {}
        finally:
            self._post(self._finish_stop)

    def _finish_stop(self):
        self._stopping = False
        self.running = False
        self.start_btn.configure(text=tr("Connect", "Подключить"), on=False,
                                 state=tk.NORMAL)
        self._update_status(False)
        self._set_text(self.info_label, tr("Disconnected.", "Отключено."))
        self._set_text(self.hero_hint,
                       tr("Tap to connect", "Нажмите, чтобы подключиться"), FG_DIM)
        self._log("Disconnected.", "INFO")
        self._update_idle_info()

    def _run_loop(self):
        loop = self._loop
        asyncio.set_event_loop(loop)
        poll_task = None
        socks_server = None
        http_server = None
        try:
            cfg = self.cfg.engine_config(self.active_profile)
            use_tun = self._use_tun()
            if use_tun:
                # Привязываем poll-запросы к физическому адаптеру: иначе
                # после --setup они уйдут в собственный TUN (петля).
                cfg.setdefault("client", {})["tun_resolve"] = True
                adapter = tun_mode.detect_physical_adapter()
                self._phys_adapter = adapter
                phys = (adapter or {}).get("ip")
                if phys:
                    cfg.setdefault("client", {})["local_address"] = phys
                    self._log(f"TUN: poll-запросы привязаны к {phys}", "INFO")
                else:
                    self._log("TUN: не удалось определить физический IPv4 — "
                              "работаем только на --bypass", "WARNING")
            self._tunnel = ClientTunnel(cfg)
            self._tunnel.set_log_callback(lambda m: self._log(m, "INFO"))
            if use_tun:
                # Резолвим имена узлов ДО поднятия TUN: сейчас ещё работает
                # обычный DNS. Иначе виртуальный DNS tun2proxy вернёт fake-IP
                # и наши же poll-запросы уйдут в собственный туннель.
                resolved = self._tunnel.resolve_host_ips()
                if not resolved:
                    self._log("TUN: не удалось заранее разрешить имена узлов; "
                              "poll-запросы могут зациклиться", "WARNING")
            self._tunnel._start_dns_relay()

            poll_task = loop.create_task(self._tunnel.poll_loop())
            socks_server, http_server = loop.run_until_complete(self._start_servers_and_wait())

            if socks_server is None or http_server is None:
                self._log("Failed to bind proxy servers", "ERROR")
                return

            if use_tun:
                # SOCKS5 уже слушает: поднимаем Wintun и заворачиваем трафик.
                self._start_tun()
            elif self._use_system_proxy():
                # Proxy/system-backend: без системного прокси приложения в
                # наш SOCKS5/HTTP не ходят.
                self._apply_system_proxy()

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
                if poll_task:
                    # Сначала гасим poll-задачу и даём ей завершиться: иначе
                    # при остановленном loop она остаётся pending и Python
                    # печатает "Task was destroyed but it is pending".
                    poll_task.cancel()
                    loop.run_until_complete(
                        asyncio.gather(poll_task, return_exceptions=True))
            except Exception:
                pass
            try:
                if self._tunnel:
                    loop.run_until_complete(self._tunnel.stop())
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
        self._set_text(self.status_label, "ONLINE" if connected else "OFFLINE", color)
        self._refresh_tray_icon()
        if connected:
            self._set_text(self.hero_hint,
                           tr("Connected · traffic is encrypted",
                              "Подключено · трафик зашифрован"), FG_GREEN)

    # ══════════════════════════════════════════════════════════════════
    #  Логи
    # ══════════════════════════════════════════════════════════════════

    def _post(self, fn, *args):
        """Планирует вызов в главном потоке (безопасно из любого потока)."""
        self._main_queue.put((fn, args))

    def _pump_main_queue(self):
        """Разбирает очередь задач главного потока. Ставится в run()."""
        while True:
            try:
                fn, args = self._main_queue.get_nowait()
            except queue.Empty:
                break
            try:
                fn(*args)
            except Exception as exc:
                logging.getLogger("vpn-gui").warning("main-queue task failed: %s", exc)
        handler = getattr(self, "_log_handler", None)
        if handler is not None:
            try:
                handler.flush_pending()
            except Exception:
                pass
        if self._pump_stopped:
            return
        try:
            self.root.after(120, self._pump_main_queue)
        except tk.TclError:
            pass

    def _log(self, msg: str, level: str = "INFO"):
        # Туннель живёт в своём потоке и зовёт лог-колбэк оттуда: tkinter
        # нельзя трогать из чужого потока, поэтому перепланируем в main.
        if threading.current_thread() is not threading.main_thread():
            self._post(self._append_log, msg, level)
            return
        self._append_log(msg, level)

    def _append_log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        for widget in (self.log_text, getattr(self, "settings_log", None)):
            if widget is None:
                continue
            try:
                at_bottom = widget.yview()[1] >= 0.999
                widget.configure(state="normal")
                widget.insert(tk.END, line + "\n", level)
                lines = int(widget.index("end-1c").split(".")[0])
                if lines > 2000:
                    widget.delete("1.0", f"{lines - 1500}.0")
                if at_bottom:
                    widget.see(tk.END)
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
        self._log_handler = handler

    # ── Жизненный цикл ──

    def run(self):
        self._setup_logging()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        self._on_hide()

    def _quit_app(self):
        if self._closing:
            return
        self._closing = True
        self._stop_config_watcher()
        self._stop_instance_server()
        if hasattr(self, "_tray") and self._tray:
            try:
                self._tray.stop()
            except Exception:
                pass
        # Прячем окно сразу, а всё остальное (TUN, loop, elevated-помощник)
        # гасим в фоне — иначе выход «зависает» на восстановлении DNS.
        self.root.withdraw()
        threading.Thread(target=self._quit_worker, daemon=True).start()

    def _quit_worker(self):
        # Если Disconnect уже идёт, дождёмся его, чтобы не дёргать TUN дважды.
        deadline = time.time() + 30.0
        while self._stopping and time.time() < deadline:
            time.sleep(0.05)
        if self.running or self._thread is not None or self._tun_active:
            self._teardown()
        helper = self._tun_helper
        self._tun_helper = None
        if helper is not None:
            try:
                helper.quit()
            except Exception:
                pass
        self._post(self._destroy_root)

    def _destroy_root(self):
        self._pump_stopped = True
        try:
            self.root.destroy()
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════════════

def _enable_dpi_awareness() -> None:
    """Чёткие шрифты и контролы на экранах с масштабом 125–200%."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        try:
            import ctypes
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main():
    # Frozen-сборка использует этот же exe как elevated-помощник TUN-режима.
    if "--tun-helper" in sys.argv:
        from vpn_helper import main as helper_main
        sys.argv = [sys.argv[0]] + [a for a in sys.argv[1:] if a != "--tun-helper"]
        sys.exit(helper_main())

    _enable_dpi_awareness()

    # Второй запуск не создаёт второе окно (иначе конфликт портов и адаптера),
    # а просто показывает уже работающее приложение из трея.
    if _raise_existing_instance():
        sys.exit(0)

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
