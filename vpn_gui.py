"""
Desktop VPN Client — GUI (tkinter, тёмная тема).

Запуск:
    python vpn_gui.py --config config.yaml

Функциональность:
  - Тёмный интерфейс в стиле VPN-приложений
  - Кнопка Start/Stop (управление туннелем + системный прокси)
  - Индикатор состояния (зелёный/красный)
  - Отображение серверов и порта
  - Лог с авто-скроллом
"""

import argparse
import asyncio
import logging
import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import time

import yaml
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import pystray
from PIL import Image, ImageDraw

# ── Импорт движка из общих модулей ──
from tunnel import ClientTunnel
from socks5_server import handle_socks_client
from desktop_client import handle_http_client, set_system_proxy_windows


# ══════════════════════════════════════════════════════════════════════
#  Цветовая палитра — Soft Dark
# ══════════════════════════════════════════════════════════════════════

BG_MAIN     = "#1e1e2e"
BG_PANEL    = "#252536"
BG_LOG      = "#1a1a28"
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
#  Главное окно
# ══════════════════════════════════════════════════════════════════════

class VpnGui:
    def __init__(self, cfg: dict, config_path: str = "config.yaml"):
        self.cfg = cfg
        self.config_path = config_path
        self._config_mtime = os.path.getmtime(config_path)
        self.running = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._tunnel: ClientTunnel | None = None
        self._observer: Observer | None = None

        client_cfg = cfg["client"]
        socks_cfg = client_cfg.get("socks5", {})
        self.socks_host = socks_cfg.get("bind_host", "0.0.0.0")
        self.socks_port = socks_cfg.get("bind_port", 8888)
        self.http_port = socks_cfg.get("http_port", 8889)

        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        self.server_urls = [u.rstrip("/") for u in urls if u]

        # ── Tk root ──
        self.root = tk.Tk()
        self.root.title("Short Polling VPN v2.0")
        self.root.geometry("540x740")
        self.root.minsize(440, 620)
        self.root.configure(bg=BG_MAIN)
        self.root.resizable(True, True)

        # Иконка (опционально)
        try:
            self.root.iconbitmap(default="")
        except Exception:
            pass

        self._build_ui()
        self._start_config_watcher()
        self._create_tray_icon()

    # ── Построение интерфейса ──

    def _build_ui(self):
        root = self.root
        FONT    = ("Segoe UI", 10)
        FONT_B  = ("Segoe UI", 10, "bold")
        FONT_S  = ("Segoe UI", 9)
        FONT_L  = ("Segoe UI", 14, "bold")

        # ═══ Заголовок ═══
        header = tk.Frame(root, bg=BG_PANEL, height=56)
        header.pack(fill=tk.X, padx=10, pady=(10, 5))
        header.pack_propagate(False)

        tk.Label(header, text="Short Polling VPN",
                 font=FONT_L, bg=BG_PANEL, fg=FG_TEXT).pack(side=tk.LEFT, padx=14)

        self.status_frame = tk.Frame(header, bg=BG_PANEL)
        self.status_frame.pack(side=tk.RIGHT, padx=14)

        self.status_dot = tk.Canvas(self.status_frame, width=12, height=12,
                                     bg=BG_PANEL, highlightthickness=0)
        self.status_dot.pack(side=tk.LEFT, padx=(0, 6))
        self._dot_id = self.status_dot.create_oval(1, 1, 11, 11, fill=FG_RED, outline="")

        self.status_label = tk.Label(self.status_frame, text="OFFLINE",
                                      font=FONT_B, bg=BG_PANEL, fg=FG_RED)
        self.status_label.pack(side=tk.LEFT)

        # ═══ Серверы ═══
        section1 = tk.Frame(root, bg=BG_PANEL)
        section1.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(section1, text="Servers", font=FONT_B,
                 bg=BG_PANEL, fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(10, 4))

        for url in self.server_urls[:3]:
            row = tk.Frame(section1, bg=BG_PANEL)
            row.pack(fill=tk.X, padx=14, pady=2)
            tk.Label(row, text="\u25cf", font=("Segoe UI", 6), bg=BG_PANEL, fg=FG_GREEN).pack(side=tk.LEFT, padx=(0, 8))
            tk.Label(row, text=url, font=("Consolas", 10), bg=BG_PANEL, fg=FG_BLUE,
                     anchor=tk.W).pack(side=tk.LEFT, fill=tk.X)

        tk.Frame(section1, bg=BG_PANEL, height=8).pack()

        # ═══ Настройки ═══
        section2 = tk.Frame(root, bg=BG_PANEL)
        section2.pack(fill=tk.X, padx=10, pady=5)

        tk.Label(section2, text="Connection", font=FONT_B,
                 bg=BG_PANEL, fg=FG_LABEL).pack(anchor=tk.W, padx=14, pady=(10, 4))

        info_grid = tk.Frame(section2, bg=BG_PANEL)
        info_grid.pack(fill=tk.X, padx=14, pady=(0, 10))

        self._info_labels = {}
        info_items = [
            ("SOCKS5:", f"{self._display_host()}:{self.socks_port}"),
            ("HTTP:", f"{self._display_host()}:{self.http_port}"),
            ("Poll:", f"{self.cfg['client'].get('poll_interval_ms', 200)} ms"),
            ("Method:", self.cfg["client"].get("poll_method", "POST")),
            ("Data:", self.cfg["client"].get("poll_data_in", "body")),
            ("TLS:", "ON" if self.cfg["client"].get("verify_tls", True) else "OFF"),
        ]
        for i, (k, v) in enumerate(info_items):
            tk.Label(info_grid, text=k, font=FONT, bg=BG_PANEL,
                     fg=FG_LABEL, anchor=tk.W).grid(row=i, column=0, sticky=tk.W, pady=2)
            lbl = tk.Label(info_grid, text=v, font=("Consolas", 10), bg=BG_PANEL,
                     fg=FG_GREEN, anchor=tk.W)
            lbl.grid(row=i, column=1, sticky=tk.W, padx=(12, 0), pady=2)
            self._info_labels[k] = lbl

        info_grid.columnconfigure(1, weight=1)

        # ═══ Кнопка ═══
        btn_frame = tk.Frame(root, bg=BG_MAIN)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)

        self.start_btn = tk.Button(
            btn_frame, text="Connect", font=FONT_L,
            bg=BTN_ON, fg="white", activebackground=BTN_HOVER_ON,
            activeforeground="white", relief=tk.FLAT, cursor="hand2",
            bd=0, command=self._on_toggle
        )
        self.start_btn.pack(fill=tk.X, ipady=4)

        self.start_btn.bind("<Enter>", self._on_btn_hover_enter)
        self.start_btn.bind("<Leave>", self._on_btn_hover_leave)

        # ═══ Статус ═══
        self.info_bar = tk.Frame(root, bg=BG_PANEL, height=32)
        self.info_bar.pack(fill=tk.X, padx=10, pady=(0, 5))
        self.info_bar.pack_propagate(False)

        self.info_label = tk.Label(self.info_bar, text="Press Connect to start",
                                    font=FONT_S, bg=BG_PANEL, fg=FG_LABEL)
        self.info_label.pack(side=tk.LEFT, padx=14, pady=4)

        self.proxy_indicator = tk.Label(self.info_bar, text="",
                                         font=FONT_S, bg=BG_PANEL)
        self.proxy_indicator.pack(side=tk.RIGHT, padx=14, pady=4)

        # ═══ Лог ═══
        log_frame = tk.Frame(root, bg=BG_MAIN)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        tk.Label(log_frame, text="Log", font=FONT_B,
                 bg=BG_MAIN, fg=FG_LABEL, anchor=tk.W).pack(anchor=tk.W, padx=4, pady=(0, 4))

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, font=("Consolas", 9),
            bg=BG_LOG, fg=FG_TEXT, insertbackground=FG_TEXT,
            selectbackground=FG_BLUE, selectforeground="white",
            relief=tk.FLAT, state="disabled", height=12,
            borderwidth=0
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("INFO", foreground=FG_TEXT)
        self.log_text.tag_config("WARNING", foreground=FG_AMBER)
        self.log_text.tag_config("ERROR", foreground=FG_RED)
        self.log_text.tag_config("DEBUG", foreground=FG_LABEL)

    def _display_host(self):
        if self.socks_host in ("0.0.0.0", ""):
            return "127.0.0.1"
        return self.socks_host

    # ── System Tray ──

    def _create_tray_icon(self):
        """Создаёт иконку в системном трее."""
        icon_image = self._create_tray_image()
        menu = pystray.Menu(
            pystray.MenuItem("Show", self._tray_show, default=True),
            pystray.MenuItem("Quit", self._tray_quit),
        )
        self._tray = pystray.Icon("VPN", icon_image, "Short Polling VPN", menu)
        self._tray_thread = threading.Thread(target=self._tray.run, daemon=True)
        self._tray_thread.start()

    def _create_tray_image(self):
        """Создаёт иконку 16x16 для трея."""
        img = Image.new("RGBA", (16, 16), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.rectangle([1, 1, 14, 14], fill="#252536", outline="#a6e3a1")
        draw.rectangle([4, 4, 11, 11], fill="#a6e3a1")
        return img

    def _tray_show(self, icon=None, item=None):
        """Показывает окно из трея (в main thread)."""
        self.root.after(0, self._show_window)

    def _show_window(self):
        """Показывает и восстанавливает окно."""
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _tray_quit(self, icon=None, item=None):
        """Полностью закрывает приложение из трея."""
        self.root.after(0, self._quit_app)

    def _on_hide(self):
        """Скрывает окно в трей."""
        self.root.withdraw()

    # ── Hover-эффекты ──

    def _on_btn_hover_enter(self, e):
        if self.running:
            self.start_btn.configure(bg=BTN_HOVER_OFF)
        else:
            self.start_btn.configure(bg=BTN_HOVER_ON)

    def _on_btn_hover_leave(self, e):
        if self.running:
            self.start_btn.configure(bg=BTN_OFF)
        else:
            self.start_btn.configure(bg=BTN_ON)

    # ── Запуск / Остановка ──

    def _on_toggle(self):
        if self.running:
            self._stop()
        else:
            self._start()

    def _start(self):
        # Перечитываем config.yaml перед подключением
        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                self.cfg = yaml.safe_load(f)
            self._config_mtime = os.path.getmtime(self.config_path)
            self._update_server_display()
        except Exception as e:
            self._log(f"Failed to reload config: {e}", "WARNING")

        self.running = True
        self.start_btn.configure(text="Disconnect", bg=BTN_OFF, fg="white")
        self._update_status(True)
        self.info_label.configure(text="Connecting...")
        self._log("VPN starting...", "INFO")

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

        # Проверяем запуск через 1.5с, затем периодически
        self.root.after(1500, self._check_started)
        self._schedule_proxy_guard()
        self._start_config_watcher()

    def _schedule_proxy_guard(self):
        """Каждые 3с проверяем, не сбросил ли кто-то прокси, и восстанавливаем."""
        if not self.running:
            return
        if sys.platform == "win32" and self.socks_host in ("0.0.0.0", "127.0.0.1", "localhost"):
            try:
                import winreg
                key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                    enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                    server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    needs_fix = (
                        not enabled
                        or "127.0.0.1" not in server
                        or str(self.http_port) not in server
                    )
                if needs_fix:
                    self._log("Proxy was overwritten — re-setting", "WARNING")
                    set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, True)
            except Exception:
                pass
        self.root.after(3000, self._schedule_proxy_guard)

    def _start_config_watcher(self):
        """Запускает watchdog observer для отслеживания изменений config.yaml."""
        self._stop_config_watcher()
        handler = ConfigFileHandler(self.config_path, self.root, self._on_config_changed)
        self._observer = Observer()
        self._observer.schedule(handler, path=os.path.dirname(os.path.abspath(self.config_path)), recursive=False)
        self._observer.start()

    def _stop_config_watcher(self):
        """Останавливает watchdog observer."""
        if self._observer and self._observer.is_alive():
            self._observer.stop()
            self._observer.join(timeout=2)
        self._observer = None

    def _on_config_changed(self):
        """Вызывается watchdog'ом в main thread при изменении config.yaml."""
        try:
            mtime = os.path.getmtime(self.config_path)
            if mtime <= self._config_mtime:
                return
            self._config_mtime = mtime
            with open(self.config_path, "r", encoding="utf-8") as f:
                new_cfg = yaml.safe_load(f)
            if new_cfg:
                self.cfg = new_cfg
                level_name = new_cfg.get("logging", {}).get("level", "INFO")
                level = getattr(logging, level_name.upper(), logging.INFO)
                logging.getLogger().setLevel(level)
                if self._tunnel:
                    self._tunnel.apply_config(new_cfg)
                client_cfg = new_cfg.get("client", {})
                urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
                self.server_urls = [u.rstrip("/") for u in urls if u]
                self._update_server_display()
                self._log("Config reloaded", "INFO")
        except Exception as e:
            self._log(f"Config reload error: {e}", "WARNING")

    def _update_server_display(self):
        """Обновляет отображение настроек в интерфейсе."""
        try:
            client_cfg = self.cfg.get("client", {})
            updates = {
                "POLL:": f"{client_cfg.get('poll_interval_ms', 200)} ms",
                "METHOD:": client_cfg.get("poll_method", "POST"),
                "DATA:": client_cfg.get("poll_data_in", "body"),
                "TLS:": "ON" if client_cfg.get("verify_tls", True) else "OFF",
            }
            for key, val in updates.items():
                if key in self._info_labels:
                    self._info_labels[key].configure(text=val)
        except Exception:
            pass

    def _check_started(self):
        if self.running and self._tunnel:
            urls_str = ", ".join(self.server_urls[:2])
            proxy_status = self._verify_system_proxy()
            conflicts = self._detect_proxy_conflicts()

            status_parts = [
                f"SK5:{self.socks_port}",
                f"HTTP:{self.http_port}",
                f"PRX:{proxy_status}"
            ]
            if conflicts:
                status_parts.append(f"CONFLICT:{conflicts}")
                self._log(f"CONFLICT DETECTED: {conflicts}", "WARNING")

            self.info_label.configure(text="  ".join(status_parts))
            self.proxy_indicator.configure(
                text=f"PROXY: {proxy_status}",
                fg=FG_GREEN if proxy_status == "SET" else FG_RED
            )

    def _verify_system_proxy(self) -> str:
        """Проверяет, что системный прокси установлен на наши порты."""
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
                has_http = "127.0.0.1" in server and str(self.http_port) in server
                if has_http:
                    return "SET"
                elif server:
                    return f"OTHER: {server}"
        except Exception:
            return "UNKNOWN"

    def _detect_proxy_conflicts(self) -> str:
        """Проверяет, не перезаписывает ли другой процесс (v2rayN и т.д.) прокси."""
        if sys.platform != "win32":
            return ""
        try:
            import winreg
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ) as key:
                enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if not enabled:
                    return ""
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                if self.http_port and str(self.http_port) not in server:
                    return f"ProxyOverride: {server}"
                if server and "127.0.0.1" in server:
                    return ""
        except Exception:
            pass

        try:
            import subprocess
            result = subprocess.run(
                ["netstat", "-ano"], capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.splitlines():
                if "10808" in line and "LISTENING" in line:
                    return "v2rayN (10808) active"
        except Exception:
            pass
        return ""

    def _stop(self):
        self.running = False
        self._stop_config_watcher()
        self.start_btn.configure(text="Connect", bg=BTN_ON, fg="white")
        self._update_status(False)
        self.info_label.configure(text="Disconnected.")
        self._log("VPN stopping...", "INFO")

        # Снимаем системный прокси
        set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, False)
        self._log(f"System proxy cleared.", "INFO")

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self._thread = None
        self._loop = None
        self._tunnel = None

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        poll_task = None
        socks_server = None
        http_server = None
        try:
            self._tunnel = ClientTunnel(self.cfg)
            self._tunnel._start_dns_relay()

            poll_task = self._loop.create_task(self._tunnel.poll_loop())

            # Запускаем SOCKS5 и HTTP прокси
            socks_server, http_server = self._loop.run_until_complete(
                self._start_servers_and_wait()
            )

            if socks_server is None or http_server is None:
                self._log("Failed to bind proxy servers", "ERROR")
                return

            # Прокси запущены — ставим системный прокси
            if sys.platform == "win32" and self.socks_host in ("0.0.0.0", "127.0.0.1", "localhost"):
                set_system_proxy_windows("127.0.0.1", self.socks_port, self.http_port, True)

            self._loop.run_forever()
        except Exception as e:
            self._log(f"FATAL: {e}", "ERROR")
        finally:
            try:
                if socks_server:
                    socks_server.close()
                    self._loop.run_until_complete(socks_server.wait_closed())
            except Exception:
                pass
            try:
                if http_server:
                    http_server.close()
                    self._loop.run_until_complete(http_server.wait_closed())
            except Exception:
                pass
            try:
                if self._tunnel:
                    self._loop.run_until_complete(self._tunnel.stop())
            except Exception:
                pass
            try:
                if poll_task:
                    poll_task.cancel()
            except Exception:
                pass

    async def _start_servers_and_wait(self):
        """Запускает SOCKS5 и HTTP прокси серверы, возвращает (socks_server, http_server)."""
        socks_server = None
        http_server = None
        try:
            socks_server = await asyncio.start_server(
                lambda r, w: handle_socks_client(self._tunnel, r, w),
                self.socks_host, self.socks_port,
                reuse_address=True
            )
            addrs = ", ".join(str(s.getsockname()) for s in socks_server.sockets)
            self._log(f"SOCKS5 listening on {addrs}", "INFO")
        except OSError as e:
            self._log(f"SOCKS5 bind failed: {e}", "ERROR")

        try:
            http_server = await asyncio.start_server(
                lambda r, w: handle_http_client(self._tunnel, r, w),
                self.socks_host, self.http_port,
                reuse_address=True
            )
            addrs = ", ".join(str(s.getsockname()) for s in http_server.sockets)
            self._log(f"HTTP CONNECT proxy listening on {addrs}", "INFO")
        except OSError as e:
            self._log(f"HTTP proxy bind failed: {e}", "ERROR")

        return socks_server, http_server

    def _update_status(self, connected: bool):
        color = FG_GREEN if connected else FG_RED
        text = "ONLINE" if connected else "OFFLINE"
        self.status_dot.itemconfig(self._dot_id, fill=color)
        self.status_label.configure(text=text, fg=color)

    def _log(self, msg: str, level: str = "INFO"):
        ts = time.strftime("%H:%M:%S")
        line = f"[{ts}] [{level}] {msg}"
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert(tk.END, line + "\n", level)
            self.log_text.see(tk.END)
            self.log_text.configure(state="disabled")
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > 2000:
                self.log_text.configure(state="normal")
                self.log_text.delete("1.0", f"{lines - 1500}.0")
                self.log_text.configure(state="disabled")
        except Exception:
            pass

    def _setup_logging(self):
        level_name = self.cfg.get("logging", {}).get("level", "INFO")
        level = getattr(logging, level_name.upper(), logging.INFO)

        handler = TkLogHandler(self.log_text)
        handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                                                datefmt="%H:%M:%S"))
        root_logger = logging.getLogger()
        root_logger.setLevel(level)
        root_logger.addHandler(handler)

    def run(self):
        self._setup_logging()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self):
        """Скрывает окно в трей вместо закрытия."""
        self._on_hide()

    def _quit_app(self):
        """Полностью закрывает приложение."""
        self._stop_config_watcher()
        if hasattr(self, '_tray') and self._tray:
            self._tray.stop()
        if self.running:
            self._stop()
        self.root.destroy()


# ══════════════════════════════════════════════════════════════════════
#  Точка входа
# ══════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="Desktop VPN Client — GUI")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    app = VpnGui(cfg, args.config)
    app.run()


if __name__ == "__main__":
    main()
