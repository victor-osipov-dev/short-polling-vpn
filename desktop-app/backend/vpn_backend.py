"""Short Polling VPN desktop backend.

Headless control process for the Electron UI:

    python vpn_backend.py --api-port 8899

It reuses the short-polling tunnel from the repository root and exposes a
small JSON API on loopback.  The Electron main process is the only client.

Design notes:
  * The tunnel event loop lives in its own thread.  HTTP handlers talk to it
    through simple thread-safe flags, never by touching asyncio objects.
  * System proxy settings are backed up and restored exactly.  If the app is
    killed, the backup is replayed on the next start.
  * TUN mode runs sing-box (bundled with the app) with a SOCKS outbound that
    points at our local SOCKS5 server.  TUN needs Administrator rights.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import ctypes
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

APP_DIR = Path(__file__).resolve().parent
if getattr(sys, "frozen", False):
    _default_core = Path(sys.executable).resolve().parent.parent / "core"
else:
    _default_core = APP_DIR.parents[1]
CORE_DIR = Path(os.environ.get("VPN_CORE_DIR") or _default_core).resolve()
sys.path.insert(0, str(CORE_DIR))

import yaml  # noqa: E402

from subscription import apply_subscription, load_subscription  # noqa: E402
from tunnel import ClientTunnel  # noqa: E402
from socks5_server import run_socks5_server  # noqa: E402
from desktop_client import run_http_proxy_server, _PROXY_OVERRIDES  # noqa: E402

APP_NAME = "Short Polling VPN"
VERSION = "1.0.0"
SOCKS_PORT = 8890
HTTP_PORT = 8891
DEFAULT_API_PORT = 8899

SETTINGS_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "ShortPollingVPN"
LEGACY_SETTINGS_DIR = Path(os.environ.get("LOCALAPPDATA") or Path.home()) / "FimdiVPN"
SETTINGS_FILE = SETTINGS_DIR / "settings.json"
PROXY_BACKUP_FILE = SETTINGS_DIR / "proxy-backup.json"

REGION_META: dict[str, dict[str, str]] = {
    "RU": {"name": "Россия", "flag": "🇷🇺", "color": "#f472b6"},
    "DE": {"name": "Германия", "flag": "🇩🇪", "color": "#fbbf24"},
    "FI": {"name": "Финляндия", "flag": "🇫🇮", "color": "#38bdf8"},
    "JP": {"name": "Япония", "flag": "🇯🇵", "color": "#fb7185"},
    "PL": {"name": "Польша", "flag": "🇵🇱", "color": "#f87171"},
    "NL": {"name": "Нидерланды", "flag": "🇳🇱", "color": "#fb923c"},
    "US": {"name": "США", "flag": "🇺🇸", "color": "#60a5fa"},
    "GB": {"name": "Великобритания", "flag": "🇬🇧", "color": "#818cf8"},
    "VPN": {"name": "VPN", "flag": "🌐", "color": "#a78bfa"},
}

# ── logging ────────────────────────────────────────────────────────────────


class LogBuffer(logging.Handler):
    def __init__(self, sink, maxlen: int = 500):
        super().__init__(level=logging.INFO)
        self.sink = sink
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = self.format(record)
        except Exception:
            msg = record.getMessage()
        self.sink(record.levelname, msg)


LOGS: deque[dict[str, Any]] = deque(maxlen=500)
LOG_LOCK = threading.Lock()


def _append_log(level: str, message: str, source: str = "vpn") -> None:
    entry = {
        "t": time.time(),
        "level": level.upper(),
        "message": message,
        "source": source,
    }
    with LOG_LOCK:
        LOGS.append(entry)
    # Keep the developer console useful when running from a terminal.
    try:
        print(f"[{entry['level']}] {message}", flush=True)
    except Exception:
        pass


class LogBridge(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        try:
            msg = record.getMessage()
            if record.exc_info:
                msg = msg + "\n" + "".join(traceback.format_exception(*record.exc_info))
            _append_log(record.levelname, msg)
        except Exception:
            pass


def setup_logging(verbose: bool = False) -> None:
    # Electron captures our stdout; force UTF-8 so Russian log lines do not
    # depend on the Windows console code page.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    root.handlers.clear()
    bridge = LogBridge()
    bridge.setLevel(logging.INFO)
    root.addHandler(bridge)
    if verbose:
        console = logging.StreamHandler(sys.stderr)
        console.setLevel(logging.INFO)
        console.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(console)
    for noisy in ("httpx", "httpcore", "urllib3"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


# ── helpers ────────────────────────────────────────────────────────────────


def is_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def load_settings() -> dict:
    # Migrate preferences from the old application name (FimdiVPN).
    try:
        if not SETTINGS_FILE.exists():
            legacy = LEGACY_SETTINGS_DIR / "settings.json"
            if legacy.exists():
                SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
                shutil.copy2(legacy, SETTINGS_FILE)
    except Exception:
        pass
    try:
        return json.loads(SETTINGS_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_settings(data: dict) -> None:
    try:
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        SETTINGS_FILE.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as exc:
        _append_log("WARNING", f"Не удалось сохранить настройки: {exc}")


def read_base_config() -> dict:
    path = CORE_DIR / "config.yaml"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:
        _append_log("WARNING", f"config.yaml не прочитан ({exc}), используются значения по умолчанию")
        return {}


def port_free(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def region_of_node(node_id: str, nodes: dict[str, dict]) -> str:
    node = nodes.get(node_id) or {}
    region = str(node.get("region") or "").upper()
    if region:
        return region
    for key, meta in REGION_META.items():
        if key != "VPN" and key.lower() in node_id.lower():
            return key
    return "VPN"


def short_chain(regions: list[str]) -> str:
    if not regions:
        return ""
    out: list[str] = []
    for r in regions:
        if not out or out[-1] != r:
            out.append(r)
    return " → ".join(out)


# ── system proxy ───────────────────────────────────────────────────────────


def _notify_proxy_change() -> None:
    try:
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


class SystemProxy:
    KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    VALUE_NAMES = ("ProxyEnable", "ProxyServer", "ProxyOverride", "AutoConfigURL")

    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.active = False

    def _read(self) -> dict:
        import winreg
        out: dict[str, Any] = {}
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_READ) as key:
                for name in self.VALUE_NAMES:
                    try:
                        value, _ = winreg.QueryValueEx(key, name)
                        out[name] = value
                    except FileNotFoundError:
                        out[name] = None
        except Exception:
            pass
        return out

    def _write(self, data: dict) -> None:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_SET_VALUE) as key:
            for name in ("ProxyEnable", "ProxyServer", "ProxyOverride"):
                if name in data and data[name] is not None:
                    winreg.SetValueEx(key, name, 0, winreg.REG_DWORD if name == "ProxyEnable" else winreg.REG_SZ, data[name])
                else:
                    try:
                        winreg.DeleteValue(key, name)
                    except FileNotFoundError:
                        pass
            pac = data.get("AutoConfigURL")
            if pac:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, pac)
            else:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
        _notify_proxy_change()

    def _ours(self, data: dict) -> bool:
        server = str(data.get("ProxyServer") or "")
        return server == f"{self.host}:{self.port}"

    def restore_stale(self) -> None:
        """Restore a backup left behind by a previous crash."""
        try:
            if not PROXY_BACKUP_FILE.exists():
                return
            backup = json.loads(PROXY_BACKUP_FILE.read_text(encoding="utf-8"))
            # On startup there is no active session to compare against, so
            # replay the saved state (proxy mode or TUN suspend).
            self._write(backup)
            _append_log("INFO", "Восстановлены настройки системного прокси после прошлого запуска")
            PROXY_BACKUP_FILE.unlink(missing_ok=True)
        except Exception as exc:
            _append_log("WARNING", f"Не удалось восстановить системный прокси: {exc}")

    def suspend(self) -> None:
        """Disable any system proxy while TUN owns all traffic, and remember
        the previous state so it can be restored on disconnect."""
        if sys.platform != "win32":
            return
        current = self._read()
        try:
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            PROXY_BACKUP_FILE.write_text(json.dumps(current, ensure_ascii=False), encoding="utf-8")
            self._write({"ProxyEnable": 0})
            _append_log("INFO", "Системный прокси временно отключён (активен TUN)")
        except Exception as exc:
            _append_log("WARNING", f"Не удалось отключить системный прокси для TUN: {exc}")

    def resume(self) -> None:
        """Restore settings saved by suspend() or by a previous crash."""
        if sys.platform != "win32":
            return
        try:
            if not PROXY_BACKUP_FILE.exists():
                return
            backup = json.loads(PROXY_BACKUP_FILE.read_text(encoding="utf-8"))
            self._write(backup)
            PROXY_BACKUP_FILE.unlink(missing_ok=True)
            _append_log("INFO", "Настройки системного прокси восстановлены")
        except Exception as exc:
            _append_log("WARNING", f"Не удалось восстановить системный прокси: {exc}")

    def enable(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("Системный прокси доступен только в Windows")
        current = self._read()
        try:
            SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
            PROXY_BACKUP_FILE.write_text(json.dumps(current, ensure_ascii=False), encoding="utf-8")
            self._write({
                "ProxyEnable": 1,
                "ProxyServer": f"{self.host}:{self.port}",
                "ProxyOverride": _PROXY_OVERRIDES,
                "AutoConfigURL": None,
            })
            self.active = True
            _append_log("INFO", f"Системный прокси включён: {self.host}:{self.port}")
        except Exception as exc:
            raise RuntimeError(f"Не удалось включить системный прокси: {exc}") from exc

    def disable(self) -> None:
        if sys.platform != "win32":
            return
        try:
            current = self._read()
            backup = None
            if PROXY_BACKUP_FILE.exists():
                try:
                    backup = json.loads(PROXY_BACKUP_FILE.read_text(encoding="utf-8"))
                except Exception:
                    backup = None
            if self.active or self._ours(current):
                if backup is not None:
                    self._write(backup)
                else:
                    self._write({"ProxyEnable": 0, "ProxyServer": None, "ProxyOverride": None, "AutoConfigURL": None})
                self.active = False
                _append_log("INFO", "Системный прокси отключён, прежние настройки восстановлены")
            PROXY_BACKUP_FILE.unlink(missing_ok=True)
        except Exception as exc:
            _append_log("WARNING", f"Не удалось выключить системный прокси: {exc}")


# ── tunnel wrapper with counters ──────────────────────────────────────────


class CountingWriter:
    def __init__(self, inner, owner):
        self._inner = inner
        self._owner = owner

    def write(self, data):
        try:
            self._owner.bytes_down += len(data)
        except Exception:
            pass
        return self._inner.write(data)

    def __getattr__(self, name):
        return getattr(self._inner, name)


class ObservableTunnel(ClientTunnel):
    def __init__(self, cfg: dict):
        super().__init__(cfg)
        self.bytes_up = 0
        self.bytes_down = 0

    async def feed_outgoing(self, sid, data):
        try:
            self.bytes_up += len(data)
        except Exception:
            pass
        await super().feed_outgoing(sid, data)

    async def register_session(self, writer, host, port, server_base=None, route=()):
        sid = await super().register_session(writer, host, port, server_base=server_base, route=route)
        sess = self.sessions.get(sid)
        if sess is not None:
            sess.writer = CountingWriter(writer, self)
        return sid


# ── application ───────────────────────────────────────────────────────────


class Backend:
    def __init__(self, api_port: int, verbose: bool = False):
        self.api_port = api_port
        self.verbose = verbose
        self.lock = threading.RLock()
        self.connect_lock = threading.Lock()
        self.settings = load_settings()
        self.base_cfg = read_base_config()
        self.sub: dict | None = None
        self.sub_url: str = str(self.settings.get("subscriptionUrl") or "")
        self.profiles: list[dict] = []
        self.subscription_meta: dict | None = None
        self.phase = "idle"
        self.mode = str(self.settings.get("mode") or "proxy")
        self.selected_profile_id: str | None = self.settings.get("profileId") or None
        self.global_mode = bool(self.settings.get("global") or False)
        self.started_at: float | None = None
        self.error: str | None = None
        self.exit_info: dict | None = None
        self.proxy = SystemProxy("127.0.0.1", HTTP_PORT)
        self.tunnel: ObservableTunnel | None = None
        self.session_thread: threading.Thread | None = None
        self.stop_flag = threading.Event()
        self.singbox: subprocess.Popen | None = None
        self.singbox_cfg_path: Path | None = None
        self.singbox_error: str | None = None
        self._added_routes: list[str] = []
        self._session_lock = threading.RLock()
        self._exit_task_loop: asyncio.AbstractEventLoop | None = None
        self._needed_urls: list[str] = []

        # If a subscription URL was saved, try to load it lazily in the
        # background so the window can paint immediately.
        if self.sub_url:
            threading.Thread(target=self._initial_subscription_load, daemon=True).start()

    # ── state ──────────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        with self.lock:
            tunnel = self.tunnel
            sessions = len(tunnel.sessions) if tunnel else 0
            polls = int(getattr(tunnel, "_poll_count", 0)) if tunnel else 0
            up = int(getattr(tunnel, "bytes_up", 0)) if tunnel else 0
            down = int(getattr(tunnel, "bytes_down", 0)) if tunnel else 0
            uptime = int(time.time() - self.started_at) if self.started_at and self.phase in ("connected", "connecting") else 0
            selected = next((p for p in self.profiles if p["id"] == self.selected_profile_id), None)
            singbox_running = bool(self.singbox and self.singbox.poll() is None)
            with LOG_LOCK:
                logs = list(LOGS)[-250:]
            return {
                "version": VERSION,
                "phase": self.phase,
                "mode": self.mode,
                "connected": self.phase == "connected",
                "profileId": self.selected_profile_id,
                "profile": selected,
                "profiles": self.profiles,
                "subscription": self.subscription_meta,
                "subscriptionUrl": self.sub_url,
                "global": self.global_mode,
                "error": self.error,
                "exit": self.exit_info,
                "admin": is_admin(),
                "ports": {"socks": SOCKS_PORT, "http": HTTP_PORT, "api": self.api_port},
                "proxy": {"active": self.proxy.active, "host": "127.0.0.1", "port": HTTP_PORT},
                "tun": {
                    "available": self._singbox_path() is not None,
                    "running": singbox_running,
                    "error": self.singbox_error,
                },
                "stats": {
                    "uptime": uptime,
                    "sessions": sessions,
                    "polls": polls,
                    "up": up,
                    "down": down,
                },
                "logs": logs,
            }

    def _set_error(self, message: str | None) -> None:
        with self.lock:
            self.error = message
            if message:
                _append_log("ERROR", message)

    # ── subscription ───────────────────────────────────────────────────

    def _initial_subscription_load(self) -> None:
        try:
            self.load_subscription(self.sub_url, persist=False)
        except Exception as exc:
            _append_log("WARNING", f"Сохранённая подписка не загрузилась: {exc}")

    def load_subscription(self, url: str, persist: bool = True) -> dict:
        url = (url or "").strip()
        if not url:
            raise ValueError("Укажите ссылку на подписку")
        _append_log("INFO", f"Загрузка подписки: {url}")
        sub = load_subscription(url, timeout=20)
        nodes = sub.get("nodes") or []
        if not isinstance(nodes, list) or not nodes:
            raise ValueError("В подписке нет узлов")
        profiles = self._build_profiles(sub)
        if not profiles:
            raise ValueError("В подписке нет профилей")
        with self.lock:
            self.sub = sub
            self.sub_url = url
            self.profiles = profiles
            self.subscription_meta = {
                "url": url,
                "loadedAt": time.time(),
                "nodes": len(nodes),
                "profiles": len(profiles),
                "user": (sub.get("user") or {}).get("name") or "",
            }
            if not any(p["id"] == self.selected_profile_id for p in profiles):
                self.selected_profile_id = profiles[0]["id"]
            self.phase = "idle" if self.phase not in ("connected", "connecting") else self.phase
            self.error = None
        if persist:
            self.settings.update({"subscriptionUrl": url, "profileId": self.selected_profile_id})
            save_settings(self.settings)
        _append_log("INFO", f"Подписка загружена: {len(nodes)} узлов, {len(profiles)} профилей")
        return self.snapshot()

    def _routes_by_name(self, sub: dict) -> dict[str, list[dict]]:
        routes: dict[str, list[dict]] = {}
        for route in sub.get("routes") or []:
            if route.get("name"):
                routes[str(route["name"])] = route.get("hops") or []
        for profile in sub.get("profiles") or []:
            for route in profile.get("routes") or []:
                if route.get("name") and str(route["name"]) not in routes:
                    routes[str(route["name"])] = route.get("hops") or []
        return routes

    def _chain_for_route(self, name: str, routes: dict[str, list[dict]],
                         nodes: dict[str, dict]) -> list[str]:
        if not name:
            return []
        if name.lower() == "direct":
            return []
        hops = routes.get(name) or []
        chain: list[str] = []
        for hop in hops:
            candidates = [str(c) for c in (hop.get("candidates") or []) if c]
            if not candidates:
                continue
            region = region_of_node(candidates[0], nodes)
            if not chain or chain[-1] != region:
                chain.append(region)
        if not chain:
            low = name.lower()
            if "герман" in low or "germany" in low:
                chain = ["DE"]
            elif "финл" in low or "finland" in low:
                chain = ["FI"]
            elif "япон" in low or "japan" in low:
                chain = ["JP"]
            elif "польш" in low or "poland" in low:
                chain = ["PL"]
            elif "росс" in low or "russia" in low:
                chain = ["RU"]
        return chain

    def _action_info(self, value: str, routes, nodes) -> dict:
        value = str(value or "").strip()
        if not value or value.lower() == "direct":
            return {"kind": "direct", "route": "", "label": "Напрямую", "chain": []}
        chain = self._chain_for_route(value, routes, nodes)
        return {"kind": "route", "route": value, "label": short_chain(chain) or value, "chain": chain}

    def _build_profiles(self, sub: dict) -> list[dict]:
        nodes_list = sub.get("nodes") or []
        nodes = {str(n.get("id")): n for n in nodes_list if n.get("id")}
        routes = self._routes_by_name(sub)
        client_profiles = sub.get("client_profiles") or []
        result: list[dict] = []

        split = sub.get("split_routing") or {}
        default_actions = split.get("actions") or {}
        default_route = ""
        default_act = default_actions.get(split.get("default", "non_ru")) or {}
        if default_act.get("route"):
            default_route = str(default_act["route"])

        if client_profiles:
            for index, p in enumerate(client_profiles):
                if not p.get("enabled", True):
                    continue
                name = str(p.get("name") or f"Профиль {index + 1}")
                route_ru = str(p.get("route_ru") or "")
                route_non = str(p.get("route_non_ru") or "")
                route_private = str(p.get("route_private") or "")
                if not route_non and not route_ru and default_route:
                    route_non = default_route
                ru = self._action_info(route_ru, routes, nodes)
                non = self._action_info(route_non, routes, nodes)
                private = self._action_info(route_private, routes, nodes)
                exit_chain = non["chain"] or ru["chain"]
                primary_chain = list(exit_chain)
                if not primary_chain and route_non:
                    primary_chain = self._chain_for_route(route_non, routes, nodes)
                region = primary_chain[-1] if primary_chain else "VPN"
                tags: list[str] = []
                all_routes = " ".join([route_ru, route_non, route_private]).lower()
                if route_non.startswith("CDN") or route_ru.startswith("CDN") or "cdn" in all_routes:
                    tags.append("CDN")
                if route_non.startswith("Direct") or route_ru.startswith("Direct"):
                    tags.append("Через Россию")
                elif len(primary_chain) > 1 and "RU" in primary_chain[:-1]:
                    tags.append("Через Россию")
                if "xhttp" in name.lower() or "xhttp" in all_routes:
                    tags.append("xhttp")
                if "mask" in all_routes or "mask" in name.lower():
                    tags.append("Резерв")
                if not route_ru and not route_non:
                    tags.append("Без split")
                result.append({
                    "id": str(p.get("id") or f"profile-{index}"),
                    "name": name,
                    "sortOrder": int(p.get("sort_order") or index),
                    "region": region,
                    "regionName": REGION_META.get(region, REGION_META["VPN"])["name"],
                    "flag": REGION_META.get(region, REGION_META["VPN"])["flag"],
                    "color": REGION_META.get(region, REGION_META["VPN"])["color"],
                    "tags": list(dict.fromkeys(tags)),
                    "split": bool(p.get("split_enabled", True)),
                    "mode": str(p.get("mode") or "vpn"),
                    "ru": ru,
                    "nonRu": non,
                    "private": private,
                    "primaryLabel": short_chain(primary_chain) if primary_chain else "VPN",
                    "chain": primary_chain,
                })
            result.sort(key=lambda x: x["sortOrder"])
            return result

        # Generic subscriptions without client_profiles: every node becomes
        # its own simple profile (all traffic through that node).
        for index, node in enumerate(nodes_list):
            if not node.get("url"):
                continue
            region = str(node.get("region") or "VPN").upper()
            name = str(node.get("name") or node.get("id") or f"Узел {index + 1}")
            result.append({
                "id": f"node:{node.get('id') or index}",
                "name": name,
                "sortOrder": index,
                "region": region,
                "regionName": REGION_META.get(region, REGION_META["VPN"])["name"],
                "flag": REGION_META.get(region, REGION_META["VPN"])["flag"],
                "color": REGION_META.get(region, REGION_META["VPN"])["color"],
                "tags": ["Весь трафик"],
                "split": False,
                "mode": "vpn",
                "ru": {"kind": "route", "route": "", "label": name, "chain": [region]},
                "nonRu": {"kind": "route", "route": "", "label": name, "chain": [region]},
                "private": {"kind": "direct", "route": "", "label": "Напрямую", "chain": []},
                "primaryLabel": name,
                "chain": [region],
                "nodeId": str(node.get("id") or ""),
                "nodeUrl": str(node.get("url")),
            })
        return result

    # ── config building ────────────────────────────────────────────────

    def _build_client_config(self, profile: dict) -> dict:
        if not self.sub:
            raise RuntimeError("Сначала загрузите подписку")
        cfg = copy.deepcopy(self.base_cfg)
        cfg["mode"] = "client"
        client = cfg.setdefault("client", {})
        client["socks5"] = {"bind_host": "127.0.0.1", "bind_port": SOCKS_PORT, "http_port": HTTP_PORT}
        client["dns_relay"] = {"enabled": False, "bind_host": "127.0.0.1", "bind_port": 5353}
        client["verify_tls"] = True
        client["trust_env_proxy"] = False
        client["server_selector"] = "random"
        client.setdefault("poll_interval_ms", 200)
        client.setdefault("poll_jitter_ms", 5)
        idle = client.setdefault("idle_timeout", {})
        idle["enabled"] = False

        apply_subscription(cfg, self.sub)
        # We already have the subscription in memory; do not re-fetch it in
        # ClientTunnel (and never install a second network dependency).
        cfg.pop("subscription", None)

        if profile.get("nodeUrl"):
            cfg["client"]["server_urls"] = [profile["nodeUrl"]]
            cfg["split_routing"] = {"enabled": False, "actions": {}}
            cfg["nodes"] = self.sub.get("nodes") or []
            return cfg

        available_routes = set((self._routes_by_name(self.sub)).keys())
        actions: dict[str, dict] = {}
        for key, info in (("ru", profile["ru"]), ("non_ru", profile["nonRu"]), ("private", profile["private"])):
            if info["kind"] == "direct":
                actions[key] = {"direct": True}
            else:
                route = info.get("route") or ""
                if route and route not in available_routes:
                    raise RuntimeError(f"Маршрут «{route}» отсутствует в подписке")
                actions[key] = {"route": route} if route else {"direct": True}

        # "Весь трафик" skips the split: every non-private host uses the
        # profile's exit route.
        if self.global_mode or not profile.get("split", True):
            exit_route = profile["nonRu"].get("route") or profile["ru"].get("route")
            if not exit_route:
                raise RuntimeError("В профиле не задан маршрут выхода")
            actions["ru"] = {"route": exit_route}
            actions["non_ru"] = {"route": exit_route}

        split = copy.deepcopy(cfg.get("split_routing") or {})
        split["enabled"] = True
        split["actions"] = actions
        cfg["split_routing"] = split

        # Only poll URLs that the selected profile can actually use.  It
        # removes dead nodes from health checks and keeps the log readable.
        needed_ids: set[str] = set()
        routes = self._routes_by_name(self.sub)
        for action in actions.values():
            route_name = action.get("route")
            if not route_name:
                continue
            for hop in routes.get(route_name) or []:
                for candidate in hop.get("candidates") or []:
                    needed_ids.add(str(candidate))
        node_urls = {
            str(n.get("id")): str(n.get("url") or "").rstrip("/")
            for n in self.sub.get("nodes") or []
            if n.get("id") and n.get("url")
        }
        needed_urls: list[str] = []
        for node_id in needed_ids:
            url = node_urls.get(node_id)
            if url and url not in needed_urls:
                needed_urls.append(url)
        if needed_urls:
            cfg["client"]["server_urls"] = needed_urls
            cfg["client"]["server_url"] = needed_urls[0]
        self._needed_urls = list(cfg["client"]["server_urls"])
        return cfg

    # ── connect / disconnect ───────────────────────────────────────────

    def _singbox_path(self) -> Path | None:
        candidates = [
            Path(os.environ.get("SPVPN_SINGBOX") or os.environ.get("FIMDI_SINGBOX") or ""),
            APP_DIR.parent / "resources" / "sing-box" / "sing-box.exe",
            Path(sys.executable).resolve().parent / "sing-box.exe",
            Path(sys.executable).resolve().parent.parent / "sing-box" / "sing-box.exe",
        ]
        for candidate in candidates:
            try:
                if candidate and candidate.is_file():
                    return candidate
            except Exception:
                continue
        found = shutil.which("sing-box")
        return Path(found) if found else None

    def connect(self, profile_id: str, mode: str, global_mode: bool) -> dict:
        if not self.connect_lock.acquire(blocking=False):
            raise RuntimeError("Подключение уже выполняется")
        try:
            with self.lock:
                profile = next((p for p in self.profiles if p["id"] == profile_id), None)
                if profile is None:
                    raise RuntimeError("Профиль не найден")
                self.mode = "tun" if mode == "tun" else "proxy"
                self.selected_profile_id = profile_id
                self.global_mode = bool(global_mode)
                self.settings.update({
                    "profileId": profile_id,
                    "mode": self.mode,
                    "global": self.global_mode,
                })
                save_settings(self.settings)

            if self.session_thread and self.session_thread.is_alive():
                self._stop_session(wait=True, clear_error=False)

            if not port_free(SOCKS_PORT) or not port_free(HTTP_PORT):
                raise RuntimeError(
                    f"Порты {SOCKS_PORT}/{HTTP_PORT} заняты. Закройте старый клиент VPN и попробуйте снова."
                )
            if self.mode == "tun" and not is_admin():
                raise RuntimeError(
                    "Для TUN-режима нужны права администратора. Перезапустите приложение от имени администратора."
                )
            if self.mode == "tun" and self._singbox_path() is None:
                raise RuntimeError("sing-box не найден рядом с приложением")

            cfg = self._build_client_config(profile)
            self._set_error(None)
            self.stop_flag.clear()
            with self.lock:
                self.phase = "connecting"
                self.started_at = time.time()
                self.exit_info = None
                self.singbox_error = None
            name = profile["name"]
            _append_log("INFO", f"Подключение: {name} ({'TUN' if self.mode == 'tun' else 'системный прокси'})")

            self.session_thread = threading.Thread(
                target=self._session_thread_main, args=(cfg, self.mode, profile), daemon=True
            )
            self.session_thread.start()

            deadline = time.time() + 25
            while time.time() < deadline:
                with self.lock:
                    if self.phase in ("connected", "error"):
                        break
                time.sleep(0.1)
            snap = self.snapshot()
            if snap["phase"] == "error":
                raise RuntimeError(snap.get("error") or "Не удалось подключиться")
            return snap
        finally:
            self.connect_lock.release()

    def disconnect(self) -> dict:
        self._stop_session(wait=True)
        return self.snapshot()

    def _stop_session(self, wait: bool = True, clear_error: bool = True) -> None:
        thread = self.session_thread
        if not thread or not thread.is_alive():
            self._cleanup_leftovers()
            with self.lock:
                if self.phase != "idle":
                    self.phase = "idle"
                self.started_at = None
            return
        with self.lock:
            self.phase = "disconnecting"
        _append_log("INFO", "Отключение…")
        self.stop_flag.set()
        if wait:
            thread.join(timeout=12)
            if thread.is_alive():
                _append_log("WARNING", "Сессия не завершилась вовремя, принудительная очистка")
                self._cleanup_leftovers()
                with self.lock:
                    self.phase = "idle"
                    self.started_at = None
        if clear_error:
            self._set_error(None)

    def _session_thread_main(self, cfg: dict, mode: str, profile: dict) -> None:
        try:
            asyncio.run(self._session_main(cfg, mode, profile))
        except Exception as exc:
            _append_log("ERROR", f"Сессия остановлена с ошибкой: {exc}")
            with self.lock:
                self.error = str(exc)
                self.phase = "error"
        finally:
            self._cleanup_leftovers()

    async def _session_main(self, cfg: dict, mode: str, profile: dict) -> None:
        tunnel = ObservableTunnel(cfg)
        with self._session_lock:
            self.tunnel = tunnel
        self._exit_task_loop = asyncio.get_running_loop()
        tunnel._start_dns_relay()

        tasks = [
            asyncio.create_task(tunnel.poll_loop(), name="poll"),
            asyncio.create_task(run_socks5_server(tunnel, "127.0.0.1", SOCKS_PORT), name="socks"),
            asyncio.create_task(run_http_proxy_server(tunnel, "127.0.0.1", HTTP_PORT), name="http"),
        ]
        await asyncio.sleep(0.8)
        for task in tasks:
            if task.done():
                exc = task.exception()
                if exc:
                    raise RuntimeError(f"Не удалось запустить локальный прокси: {exc}")
        _append_log("INFO", f"Локальные прокси готовы: SOCKS5 127.0.0.1:{SOCKS_PORT}, HTTP 127.0.0.1:{HTTP_PORT}")

        try:
            if mode == "proxy":
                self.proxy.enable()
            else:
                # A stale system proxy (v2rayN, old client, etc.) would
                # intercept traffic while TUN is active and break the internet.
                self.proxy.suspend()
                await asyncio.to_thread(self._start_singbox, tunnel)

            with self.lock:
                self.phase = "connected"
                self.started_at = time.time()
            _append_log("INFO", f"Туннель поднят: {profile['name']}")

            exit_task = asyncio.create_task(self._check_exit())
            tasks.append(exit_task)
            if mode == "tun":
                tasks.append(asyncio.create_task(self._watch_singbox()))

            while not self.stop_flag.is_set():
                await asyncio.sleep(0.25)
        finally:
            _append_log("INFO", "Остановка локальных прокси…")
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            try:
                await tunnel.http.aclose()
            except Exception:
                pass
            await asyncio.to_thread(self._stop_singbox)
            self.proxy.disable()
            self.proxy.resume()
            with self._session_lock:
                self.tunnel = None
            with self.lock:
                if self.phase != "error":
                    self.phase = "idle"
                self.started_at = None
                self.exit_info = None

    # ── TUN ────────────────────────────────────────────────────────────

    def _resolve_node_ips(self) -> list[str]:
        addresses: set[str] = {
            # Local DNS must bypass TUN; the tunnel nodes themselves are
            # excluded below so polling cannot feed back into sing-box.
            "223.5.5.5/32",
            "8.8.8.8/32",
        }
        sub = self.sub or {}
        urls = list(self._needed_urls or [])
        if not urls:
            urls = [str(n.get("url") or "") for n in sub.get("nodes") or []]
        for url in urls:
            if not url:
                continue
            try:
                from urllib.parse import urlsplit
                host = urlsplit(url).hostname
                if not host:
                    continue
                for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM):
                    ip = item[4][0]
                    if ":" not in ip:
                        addresses.add(f"{ip}/32")
            except Exception:
                continue
        return sorted(addresses)

    def _tun_config(self) -> dict:
        excluded = self._resolve_node_ips()
        config = {
            "log": {"level": "warn", "timestamp": True},
            "dns": {
                "servers": [
                    {"tag": "proxy-dns", "type": "https", "server": "1.1.1.1", "detour": "socks-out"},
                    {"tag": "local-dns", "type": "udp", "server": "223.5.5.5", "detour": "direct"},
                ],
                "final": "proxy-dns",
            },
            "inbounds": [
                {
                    "type": "tun",
                    "tag": "tun-in",
                    "interface_name": "fimdi-tun",
                    "address": ["172.19.0.1/30"],
                    "mtu": 1400,
                    "auto_route": True,
                    "strict_route": False,
                    "stack": "mixed",
                    "route_exclude_address": excluded,
                }
            ],
            "outbounds": [
                {
                    "type": "socks",
                    "tag": "socks-out",
                    "server": "127.0.0.1",
                    "server_port": SOCKS_PORT,
                    "version": "5",
                },
                {"type": "direct", "tag": "direct", "domain_resolver": "proxy-dns"},
            ],
            "route": {
                "rules": [
                    {"action": "sniff"},
                    {"protocol": "dns", "action": "hijack-dns"},
                    {"ip_is_private": True, "outbound": "direct"},
                    {"process_name": ["python.exe", "pythonw.exe", "vpn-backend.exe"], "outbound": "direct"},
                    # Our SOCKS5 upstream only supports TCP CONNECT. Reject
                    # other UDP flows (QUIC etc.) so apps fall back to TCP
                    # instead of asking sing-box for UDP ASSOCIATE.
                    {"network": "udp", "action": "reject"},
                ],
                "final": "socks-out",
                "auto_detect_interface": True,
                "default_domain_resolver": "proxy-dns",
            },
        }
        return config

    def _physical_gateway(self) -> str:
        if sys.platform != "win32":
            return ""
        script = (
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Where-Object { $_.NextHop -and $_.NextHop -ne '0.0.0.0' } | "
            "Sort-Object RouteMetric | Select-Object -First 1).NextHop"
        )
        try:
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-Command", script],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            gateway = (result.stdout or "").strip().splitlines()
            return gateway[0].strip() if gateway else ""
        except Exception:
            return ""

    def _add_poll_routes(self) -> None:
        """Pin node IPs to the physical gateway before TUN takes over."""
        if sys.platform != "win32":
            return
        gateway = self._physical_gateway()
        if not gateway:
            _append_log("WARNING", "Не найден физический шлюз — polling может идти через TUN")
            return
        for cidr in self._resolve_node_ips():
            ip = cidr.split("/")[0]
            try:
                result = subprocess.run(
                    ["route", "add", ip, "mask", "255.255.255.255", gateway, "metric", "1"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                if result.returncode == 0:
                    self._added_routes.append(ip)
                else:
                    _append_log("WARNING", f"Не удалось добавить маршрут {ip}: {(result.stderr or '').strip()[:120]}")
            except Exception as exc:
                _append_log("WARNING", f"Не удалось добавить маршрут {ip}: {exc}")
        if self._added_routes:
            _append_log("INFO", f"Маршруты к узлам ({len(self._added_routes)}) идут мимо TUN")

    def _remove_poll_routes(self) -> None:
        if sys.platform != "win32":
            return
        for ip in list(self._added_routes):
            try:
                subprocess.run(
                    ["route", "delete", ip],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception:
                pass
        if self._added_routes:
            _append_log("INFO", "Специальные маршруты к узлам удалены")
        self._added_routes.clear()

    def _cleanup_stale_tun(self) -> None:
        """Kill leftovers from a previous crash and remove their adapters."""
        if sys.platform != "win32":
            return
        script = r"""
$procs = Get-CimInstance Win32_Process -Filter "Name='sing-box.exe'" -ErrorAction SilentlyContinue
foreach ($p in $procs) {
  $cl = [string]$p.CommandLine
  if ($cl -like '*sing-box-tun.json*' -or $cl -like '*ShortPollingVPN*' -or $cl -like '*FimdiVPN*') {
    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
  }
}
Start-Sleep -Milliseconds 500
Get-NetAdapter -ErrorAction SilentlyContinue |
  Where-Object { $_.Name -in @('fimdi-tun','singbox_tun') } |
  Remove-NetAdapter -Force -Confirm:$false -ErrorAction SilentlyContinue
"""
        try:
            subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            _append_log("WARNING", f"Не удалось убрать старый TUN-адаптер: {exc}")

    def _start_singbox(self, tunnel: ObservableTunnel) -> None:
        binary = self._singbox_path()
        if not binary:
            raise RuntimeError("sing-box не найден")
        config = self._tun_config()
        SETTINGS_DIR.mkdir(parents=True, exist_ok=True)
        path = SETTINGS_DIR / "sing-box-tun.json"
        path.write_text(json.dumps(config, ensure_ascii=False, indent=2), encoding="utf-8")
        self.singbox_cfg_path = path

        # Validate first: a bad config should be a clear error, not a silently
        # dead TUN adapter.
        check = subprocess.run(
            [str(binary), "check", "-c", str(path)],
            capture_output=True, text=True, timeout=20,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if check.returncode != 0:
            raise RuntimeError(f"sing-box отклонил конфигурацию: {(check.stderr or check.stdout).strip()[:500]}")

        # Keep polling traffic out of the TUN interface.  Specific host routes
        # win over the default route that sing-box installs.
        self._add_poll_routes()

        _append_log("INFO", "Запуск sing-box TUN (нужны права администратора)…")
        proc = subprocess.Popen(
            [str(binary), "run", "-c", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            cwd=str(binary.parent),
        )
        self.singbox = proc
        threading.Thread(target=self._read_singbox_logs, args=(proc,), daemon=True).start()
        time.sleep(0.6)
        if proc.poll() is not None:
            raise RuntimeError(f"sing-box завершился: {self.singbox_error or 'неизвестная ошибка'}")
        _append_log("INFO", "sing-box TUN запущен")

    @staticmethod
    def _clean_ansi(text: str) -> str:
        import re
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text).strip()

    def _read_singbox_logs(self, proc: subprocess.Popen) -> None:
        try:
            assert proc.stdout is not None
            for raw in proc.stdout:
                line = self._clean_ansi(raw)
                if not line:
                    continue
                low = line.lower()
                # Only a fatal error should be shown in the UI.  Routine
                # per-connection errors (UDP/QUIC, DNS timeouts) are normal
                # with a TCP-only SOCKS upstream and go to the log only.
                fatal = "fatal" in low or "panic" in low
                if fatal:
                    self.singbox_error = line
                level = "ERROR" if fatal else ("WARNING" if "error" in low else "INFO")
                _append_log(level, f"sing-box: {line}")
        except Exception:
            pass
        finally:
            if proc.poll() is not None and not self.stop_flag.is_set():
                self.singbox_error = self.singbox_error or f"sing-box завершился с кодом {proc.returncode}"
                _append_log("ERROR", self.singbox_error)

    async def _watch_singbox(self) -> None:
        while not self.stop_flag.is_set():
            await asyncio.sleep(1.0)
            proc = self.singbox
            if proc and proc.poll() is not None and not self.stop_flag.is_set():
                with self.lock:
                    self.error = self.singbox_error or "sing-box неожиданно завершился"
                    self.phase = "error"
                _append_log("ERROR", self.error)
                self.stop_flag.set()
                return

    def _stop_singbox(self) -> None:
        proc = self.singbox
        self.singbox = None
        if not proc:
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=5)
            _append_log("INFO", "sing-box остановлен")
        except Exception as exc:
            _append_log("WARNING", f"Не удалось остановить sing-box: {exc}")
        finally:
            try:
                if self.singbox_cfg_path:
                    self.singbox_cfg_path.unlink(missing_ok=True)
            except Exception:
                pass
            self._remove_poll_routes()
            self._cleanup_stale_tun()

    # ── exit check ─────────────────────────────────────────────────────

    async def _check_exit(self) -> None:
        await asyncio.sleep(1.0)
        for attempt in range(3):
            if self.stop_flag.is_set():
                return
            try:
                data = await asyncio.to_thread(self._fetch_exit_info)
                with self.lock:
                    self.exit_info = data
                ip = data.get("ip") or "?"
                country = data.get("countryCode") or ""
                _append_log("INFO", f"Внешний IP: {ip}{(' · ' + country) if country else ''}")
                return
            except Exception as exc:
                if attempt == 2:
                    with self.lock:
                        self.exit_info = {"ip": None, "error": str(exc), "checkedAt": time.time()}
                    _append_log("WARNING", f"Не удалось проверить внешний IP: {exc}")
                else:
                    await asyncio.sleep(2.0 + attempt * 2)

    def _fetch_exit_info(self) -> dict:
        proxy = f"http://127.0.0.1:{HTTP_PORT}"
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy})
        )
        # Cloudflare's trace endpoint is not present in the project's
        # "Russian domains" list, so the request really goes through the
        # selected exit.  ipinfo.io/x.com are in that list and would be
        # routed directly by split routing.
        req = urllib.request.Request(
            "https://www.cloudflare.com/cdn-cgi/trace",
            headers={"User-Agent": "short-polling-vpn/1.0"},
        )
        with opener.open(req, timeout=18) as resp:
            text = resp.read().decode("utf-8", "replace")
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                fields[key.strip()] = value.strip()
        ip = fields.get("ip") or ""
        if not ip:
            raise RuntimeError("пустой ответ сервиса проверки IP")
        return {
            "ip": ip,
            "countryCode": "",
            "city": "",
            "org": "",
            "checkedAt": time.time(),
        }

    # ── cleanup / shutdown ─────────────────────────────────────────────

    def _cleanup_leftovers(self) -> None:
        try:
            self._stop_singbox()
        except Exception:
            pass
        try:
            if self.proxy.active:
                self.proxy.disable()
        except Exception:
            pass
        with self.lock:
            self.tunnel = None

    def shutdown(self) -> None:
        self._stop_session(wait=True)
        with self.lock:
            self.phase = "idle"
        self.proxy.disable()


# ── HTTP API ───────────────────────────────────────────────────────────────


class ApiHandler(BaseHTTPRequestHandler):
    backend: Backend

    def log_message(self, fmt, *args):  # silence default access log
        return

    def _send(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            data = json.loads(raw.decode("utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            raise ValueError("Некорректный JSON")

    def do_OPTIONS(self):
        self._send(200, {"ok": True})

    def do_GET(self):
        try:
            if self.path.startswith("/api/health"):
                self._send(200, {"ok": True, "version": VERSION, "admin": is_admin()})
            elif self.path.startswith("/api/state"):
                self._send(200, self.backend.snapshot())
            elif self.path.startswith("/api/logs"):
                with LOG_LOCK:
                    self._send(200, {"logs": list(LOGS)[-300:]})
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:
            self._send(500, {"error": str(exc)})

    def do_POST(self):
        try:
            data = self._read_json()
            if self.path.startswith("/api/subscription"):
                url = str(data.get("url") or "")
                snap = self.backend.load_subscription(url)
                self._send(200, {"ok": True, "state": snap})
            elif self.path.startswith("/api/connect"):
                profile_id = str(data.get("profileId") or "")
                mode = str(data.get("mode") or "proxy")
                global_mode = bool(data.get("global") or False)
                snap = self.backend.connect(profile_id, mode, global_mode)
                self._send(200, {"ok": True, "state": snap})
            elif self.path.startswith("/api/disconnect"):
                snap = self.backend.disconnect()
                self._send(200, {"ok": True, "state": snap})
            elif self.path.startswith("/api/recheck"):
                loop = self.backend._exit_task_loop
                if loop and loop.is_running() and self.backend.phase == "connected":
                    asyncio.run_coroutine_threadsafe(self.backend._check_exit(), loop)
                self._send(200, {"ok": True, "state": self.backend.snapshot()})
            elif self.path.startswith("/api/shutdown"):
                self._send(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            else:
                self._send(404, {"error": "not found"})
        except Exception as exc:
            _append_log("ERROR", str(exc))
            self._send(400, {"error": str(exc)})


def main() -> None:
    parser = argparse.ArgumentParser(description="Short Polling VPN desktop backend")
    parser.add_argument("--api-port", type=int, default=DEFAULT_API_PORT)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    setup_logging(args.verbose)
    _append_log("INFO", f"Short Polling VPN backend {VERSION} запущен (API 127.0.0.1:{args.api_port})")
    if not is_admin():
        _append_log("INFO", "Приложение запущено без прав администратора — TUN-режим будет недоступен")

    backend = Backend(args.api_port, verbose=args.verbose)
    if is_admin():
        backend._cleanup_stale_tun()
    backend.proxy.restore_stale()

    handler = type("BoundApiHandler", (ApiHandler,), {"backend": backend})
    server = ThreadingHTTPServer(("127.0.0.1", args.api_port), handler)
    server.daemon_threads = True
    _append_log("INFO", "API готов")
    try:
        server.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        backend.shutdown()
        _append_log("INFO", "Backend остановлен")


if __name__ == "__main__":
    main()
