"""Настоящий TUN-режим для Windows (Wintun через tun2proxy).

Модуль отвечает за три вещи:

1. Поиск bundled `bin/win/tun2proxy-bin.exe` + `wintun.dll`.
2. Запуск tun2proxy, который создаёт Wintun-адаптер, заворачивает в него
   весь трафик (`--setup`) и отдаёт его локальному SOCKS5 нашего туннеля.
3. Elevated-помощник: GUI запускает отдельный процесс с правами
   администратора **один раз на запуск приложения** (запрос UAC), дальше
   команды start/stop идут по localhost без повторных запросов.

Почему так: Wintun требует прав администратора. Держать весь GUI elevated
незачем — он трогает файловые диалоги, трей и т.п. Помощник же умеет
ровно одно: поднять/остановить tun2proxy.

Безопасность помощника: слушает только 127.0.0.1, требует случайный токен
из командной строки, выходит по `quit`.

Зачем нужен `local_address`: с `--setup` tun2proxy ставит default-route
на TUN. Тогда наши же poll-запросы к серверу ушли бы в TUN и зациклились
(TUN → SOCKS → снова TUN). Привязка исходящего сокета к IP физического
адаптера (на Windows выбор маршрута учитывает source address) оставляет
их в обход туннеля, а `--bypass <ip узлов>` дублирует это на уровне routes.

DNS: наш SOCKS5 умеет только TCP CONNECT, поэтому UDP-резолвинг через
прокси не работает. По умолчанию используем `--dns virtual` — tun2proxy
сам отвечает на DNS и передаёт доменные имена дальше, а это ещё и даёт
split-routing настоящий hostname для каждой сессии.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import logging
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlparse

logger = logging.getLogger("vpn-tun")

IS_WINDOWS = sys.platform == "win32"
DEFAULT_TUN_MTU = 1500
DEFAULT_DNS_MODE = "virtual"  # virtual | over-tcp | direct
DEFAULT_HELPER_PORT = 41417
# Сколько elevated-помощник ждёт нового подключения GUI после отключения.
# В этом окне повторный запуск приложения не требует UAC, но забытый
# административный процесс не остаётся навсегда.
HELPER_IDLE_TIMEOUT = 900.0

# Описания/алиасы адаптеров, которые считаем «виртуальными» и не берём
# как физический выход в интернет.
_VIRTUAL_HINTS = (
    "tun", "wintun", "sing", "tap", "wireguard", "openvpn", "tailscale",
    "zerotier", "vpn", "virtual", "loopback", "hyper-v", "teredo", "isatap",
    "pseudo", "kernel debug", "bluetooth", "wi-fi direct", "miniport",
)


# ══════════════════════════════════════════════════════════════════════
#  Поиск bundled-бинарников
# ══════════════════════════════════════════════════════════════════════

def _app_roots() -> list[Path]:
    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(__file__).resolve().parent)
    if getattr(sys, "frozen", False):
        roots.append(Path(sys.executable).resolve().parent)
    seen: list[Path] = []
    for r in roots:
        if r not in seen:
            seen.append(r)
    return seen


def bin_dir() -> Optional[Path]:
    for root in _app_roots():
        cand = root / "bin" / "win"
        if cand.is_dir():
            return cand
    return None


def tun2proxy_path() -> Optional[Path]:
    d = bin_dir()
    if d is None:
        return None
    exe = d / "tun2proxy-bin.exe"
    return exe if exe.is_file() else None


def wintun_dll_path() -> Optional[Path]:
    d = bin_dir()
    if d is None:
        return None
    dll = d / "wintun.dll"
    return dll if dll.is_file() else None


def tun_available() -> bool:
    """Готов ли TUN-режим: Windows + tun2proxy + wintun на месте."""
    return IS_WINDOWS and tun2proxy_path() is not None and wintun_dll_path() is not None


def is_admin() -> bool:
    if not IS_WINDOWS:
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════
#  Сеть: физический адрес и bypass-адреса серверов
# ══════════════════════════════════════════════════════════════════════

def _run_powershell(script: str, timeout: float = 15.0) -> str:
    """Запускает PowerShell и возвращает stdout (UTF-8)."""
    if not IS_WINDOWS:
        return ""
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + script,
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        logger.debug("powershell failed: %s", exc)
        return ""
    return out.stdout.decode("utf-8", "replace")


_PS_ADAPTERS = (
    "Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' -and "
    "$_.IPv4DefaultGateway } | ForEach-Object { [pscustomobject]@{ "
    "alias=$_.InterfaceAlias; ip=$_.IPv4Address.IPAddress; "
    "desc=$_.NetAdapter.InterfaceDescription } } | ConvertTo-Json -Compress"
)


def _looks_virtual(text: str) -> bool:
    low = (text or "").lower()
    return any(h in low for h in _VIRTUAL_HINTS)


def detect_physical_ipv4() -> Optional[str]:
    """IPv4 физического адаптера с default gateway (Wi-Fi/Ethernet).

    Нужен, чтобы привязать исходящие poll-запросы в обход TUN. Возвращает
    None, если определить не удалось (тогда работаем только на --bypass).
    """
    adapter = detect_physical_adapter()
    if adapter:
        return adapter.get("ip") or None
    return None


_PS_PHYSICAL = (
    "Get-NetIPConfiguration | Where-Object { $_.NetAdapter.Status -eq 'Up' "
    "-and $_.IPv4DefaultGateway } | ForEach-Object { "
    "$guid = $_.NetAdapter.InterfaceGuid; "
    "$p = \"HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\$guid\"; "
    "$st = (Get-ItemProperty -Path $p -Name NameServer -ErrorAction SilentlyContinue).NameServer; "
    "[pscustomobject]@{ alias=$_.InterfaceAlias; ip=$_.IPv4Address.IPAddress; "
    "desc=$_.NetAdapter.InterfaceDescription; static=[string]$st; "
    "effective=@((Get-DnsClientServerAddress -InterfaceIndex $_.InterfaceIndex "
    "-AddressFamily IPv4).ServerAddresses) } } | ConvertTo-Json -Compress"
)


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [v.strip() for v in value.replace(",", " ").split() if v.strip()]
    if isinstance(value, (list, tuple)):
        out: list[str] = []
        for item in value:
            out.extend(_as_list(item))
        return out
    return [str(value).strip()]


def _physical_entries() -> list[dict]:
    raw = _run_powershell(_PS_PHYSICAL)
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        logger.debug("physical adapter json parse failed: %s", exc)
        return []
    if isinstance(parsed, dict):
        parsed = [parsed]
    return [e for e in parsed if isinstance(e, dict)]


def detect_physical_adapter(prefer_alias: str = "") -> Optional[dict]:
    """Физический адаптер: alias, ipv4, описание и текущие DNS-серверы.

    Важно смотреть ВСЕ адаптеры, а не первый: когда наш TUN уже поднят,
    `Get-NetIPConfiguration` может вернуть его первым. Виртуальные
    адаптеры (tun/wintun/vpn/...) отбрасываются.
    """
    entries = _physical_entries()
    candidates: list[dict] = []
    for entry in entries:
        ip = str(entry.get("ip") or "").strip()
        alias = str(entry.get("alias") or "").strip()
        desc = str(entry.get("desc") or "")
        if not ip or ":" in ip or not alias:
            continue
        if _looks_virtual(desc) or _looks_virtual(alias):
            continue
        candidates.append(entry)

    if prefer_alias:
        for entry in candidates:
            if str(entry.get("alias")) == prefer_alias:
                return {
                    "alias": str(entry.get("alias")),
                    "ip": str(entry.get("ip") or ""),
                    "desc": str(entry.get("desc") or ""),
                    "static": str(entry.get("static") or "").strip(),
                    "effective": _as_list(entry.get("effective")),
                }

    if candidates:
        entry = candidates[0]
        return {
            "alias": str(entry.get("alias")),
            "ip": str(entry.get("ip") or ""),
            "desc": str(entry.get("desc") or ""),
            "static": str(entry.get("static") or "").strip(),
            "effective": _as_list(entry.get("effective")),
        }

    # Запасной путь: маршрутом по умолчанию узнаём source IP. Если сейчас
    # активен чужой TUN, вернётся его адрес — тогда лучше None.
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
        finally:
            s.close()
        if ip and not ip.startswith("0.") and not ip.startswith("172.18.") \
                and not ip.startswith("10.0.0.") and not ip.startswith("198.18."):
            return {"alias": "", "ip": ip, "desc": "", "static": "", "effective": []}
    except Exception:
        pass
    return None


# ══════════════════════════════════════════════════════════════════════
#  DNS: перенаправление резолвера физического адаптера в TUN
# ══════════════════════════════════════════════════════════════════════

TUN_GATEWAY = "10.0.0.1"
DNS_STATE_FILE = Path(tempfile.gettempdir()) / "vpnclient_dns_state.json"


def _ps_run(script: str, timeout: float = 25.0) -> tuple[int, str]:
    if not IS_WINDOWS:
        return 1, "not windows"
    cmd = [
        "powershell", "-NoProfile", "-NonInteractive", "-Command",
        "[Console]::OutputEncoding=[Text.Encoding]::UTF8; $ErrorActionPreference='Stop'; "
        + script,
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:
        return 1, str(exc)
    text = (out.stdout or b"").decode("utf-8", "replace").strip()
    if out.returncode != 0:
        err = (out.stderr or b"").decode("utf-8", "replace").strip()
        return out.returncode, (err or text)
    return 0, text


def _set_interface_dns(alias: str, servers: list[str]) -> bool:
    if not alias:
        return False
    addrs = ",".join("'" + s.replace("'", "''") + "'" for s in servers if s)
    safe_alias = alias.replace("'", "''")
    rc, out = _ps_run(
        f"Set-DnsClientServerAddress -InterfaceAlias '{safe_alias}' "
        f"-ServerAddresses @({addrs})")
    if rc != 0:
        logger.warning("set DNS on %s failed: %s", alias, out)
        return False
    _ps_run("Clear-DnsClientCache")
    return True


def _reset_interface_dns(alias: str) -> bool:
    if not alias:
        return False
    safe_alias = alias.replace("'", "''")
    rc, out = _ps_run(
        f"Set-DnsClientServerAddress -InterfaceAlias '{safe_alias}' -ResetServerAddresses")
    if rc != 0:
        logger.warning("reset DNS on %s failed: %s", alias, out)
        return False
    _ps_run("Clear-DnsClientCache")
    return True


def _write_dns_state(state: dict) -> None:
    try:
        DNS_STATE_FILE.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
    except Exception as exc:
        logger.debug("cannot write DNS state: %s", exc)


def _read_dns_state() -> Optional[dict]:
    try:
        if DNS_STATE_FILE.is_file():
            data = json.loads(DNS_STATE_FILE.read_text(encoding="utf-8"))
            if isinstance(data, dict) and data.get("alias"):
                return data
    except Exception as exc:
        logger.debug("cannot read DNS state: %s", exc)
    return None


def _drop_dns_state() -> None:
    try:
        DNS_STATE_FILE.unlink()
    except Exception:
        pass


def restore_dns_from_state() -> bool:
    """Возвращает DNS физического адаптера, если прошлый запуск не убрал его."""
    state = _read_dns_state()
    if not state:
        return False
    alias = str(state.get("alias") or "")
    static = _as_list(state.get("static"))
    ok = _set_interface_dns(alias, static) if static else _reset_interface_dns(alias)
    logger.info("DNS на %s восстановлен (%s)", alias, static or "DHCP")
    _drop_dns_state()
    return ok


def hijack_dns_to_tun(adapter: Optional[dict] = None) -> Optional[dict]:
    """Переключает DNS физического адаптера на шлюз TUN (10.0.0.1).

    Без этого Windows продолжает спрашивать DNS провайдера параллельно с
    TUN (smart multi-homed name resolution) — это утечка имён. После
    переключения все запросы попадают в tun2proxy virtual DNS, а имена
    уходят на сервер уже внутри SOCKS5.
    """
    if not IS_WINDOWS:
        return None
    adapter = adapter or detect_physical_adapter()
    if not adapter or not adapter.get("alias"):
        logger.warning("DNS hijack: не удалось определить физический адаптер")
        return None
    alias = str(adapter["alias"])
    state = {
        "alias": alias,
        "static": str(adapter.get("static") or ""),
        "effective": _as_list(adapter.get("effective")),
    }
    _write_dns_state(state)
    if not _set_interface_dns(alias, [TUN_GATEWAY]):
        _drop_dns_state()
        return None
    logger.info("DNS на %s -> %s (было %s)", alias, TUN_GATEWAY,
                state["effective"] or state["static"] or "DHCP")
    return state


def resolve_ipv4(hostnames: list[str]) -> list[str]:
    out: list[str] = []
    for host in hostnames:
        host = (host or "").strip()
        if not host:
            continue
        try:
            infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        except Exception:
            continue
        for info in infos:
            ip = info[4][0]
            if ip not in out:
                out.append(ip)
    return out


def hosts_from_urls(urls: list[str]) -> list[str]:
    hosts: list[str] = []
    for url in urls or []:
        try:
            host = urlparse(str(url)).hostname
        except Exception:
            host = None
        if host and host not in hosts:
            hosts.append(host)
    return hosts


def server_ipv4s(server_urls: list[str]) -> list[str]:
    """IPv4 всех узлов подписки — их tun2proxy отправит в обход TUN."""
    ips: list[str] = []
    for ip in resolve_ipv4(hosts_from_urls(server_urls)):
        if ip not in ips:
            ips.append(ip)
    return ips


def literal_ips_from_urls(urls: list[str]) -> list[str]:
    """Только те «хосты», что уже являются IPv4-литералами (без DNS)."""
    out: list[str] = []
    for host in hosts_from_urls(urls):
        try:
            if not ipaddress.IPv4Address(host):
                continue
        except ValueError:
            continue
        if host not in out:
            out.append(host)
    return out


def default_route_alias() -> Optional[str]:
    """Алиас адаптера, через который сейчас идёт default-route (для логов)."""
    script = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
        "Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 "
        "-ExpandProperty InterfaceAlias"
    )
    alias = _run_powershell(script).strip().splitlines()
    return alias[0].strip() if alias and alias[0].strip() else None


def pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])
    finally:
        s.close()


# ══════════════════════════════════════════════════════════════════════
#  Супервизор tun2proxy (внутри elevated-помощника)
# ══════════════════════════════════════════════════════════════════════

class TunProcess:
    """Запускает и останавливает tun2proxy-bin.exe."""

    def __init__(self, on_log: Optional[Callable[[str], None]] = None):
        self._on_log = on_log
        self._proc: Optional[subprocess.Popen] = None
        self._reader: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._dns_hijacked = False

    def _log(self, line: str) -> None:
        if self._on_log:
            try:
                self._on_log(line)
            except Exception:
                pass
        else:
            logger.info("%s", line)

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def build_argv(self, socks_host: str, socks_port: int, *,
                   mtu: int = DEFAULT_TUN_MTU,
                   dns_mode: str = DEFAULT_DNS_MODE,
                   bypass_ips: Optional[list[str]] = None,
                   verbosity: str = "info",
                   tun_name: str = "") -> list[str]:
        exe = tun2proxy_path()
        if exe is None:
            raise FileNotFoundError("tun2proxy-bin.exe not found (bin/win)")
        argv = [
            str(exe),
            "--setup",
            "--proxy", f"socks5://{socks_host}:{socks_port}",
            "--mtu", str(int(mtu)),
            "--dns", str(dns_mode),
            "--verbosity", str(verbosity),
        ]
        if tun_name:
            argv += ["--tun", str(tun_name)]
        for ip in bypass_ips or []:
            ip = str(ip).strip()
            if ip:
                argv += ["--bypass", ip]
        return argv

    def start(self, socks_host: str, socks_port: int, **kwargs) -> int:
        if self.is_running():
            raise RuntimeError("tun2proxy already running")
        if not is_admin():
            raise PermissionError(
                "TUN-режим требует прав администратора (Wintun). "
                "Подтвердите запрос UAC."
            )
        dns_hijack = bool(kwargs.pop("dns_hijack", True))
        physical_alias = str(kwargs.pop("physical_alias", "") or "")
        physical_ip = str(kwargs.pop("physical_ip", "") or "")
        exe = tun2proxy_path()
        argv = self.build_argv(socks_host, socks_port, **kwargs)
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self._log("Запуск: " + " ".join(argv))
        with self._lock:
            # cwd = каталог tun2proxy, чтобы он нашёл рядом wintun.dll.
            self._proc = subprocess.Popen(
                argv, cwd=str(exe.parent),
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                creationflags=creationflags, bufsize=1,
            )
        self._reader = threading.Thread(target=self._pump_output,
                                        args=(self._proc,), daemon=True)
        self._reader.start()
        if dns_hijack:
            threading.Thread(target=self._apply_dns_hijack,
                             args=(physical_alias, physical_ip), daemon=True).start()
        return self._proc.pid

    def _apply_dns_hijack(self, alias: str = "", ip: str = "") -> None:
        # Даём tun2proxy время создать адаптер и прописать маршруты.
        time.sleep(2.0)
        if not self.is_running():
            self._log("DNS: tun2proxy не запустился, DNS не меняю")
            return
        adapter = detect_physical_adapter(prefer_alias=alias)
        if adapter is None and alias:
            adapter = {"alias": alias, "ip": ip, "desc": "", "static": "",
                       "effective": []}
        state = hijack_dns_to_tun(adapter)
        if state:
            if not self.is_running():
                # Пока шёл PowerShell, tun2proxy уже остановили — не оставляем
                # DNS переключённым на несуществующий шлюз.
                restore_dns_from_state()
                return
            self._dns_hijacked = True
            self._log(f"DNS переключён на {TUN_GATEWAY}: утечки имён нет")
        else:
            self._log("DNS не переключён: Windows может опрашивать DNS провайдера")

    def _pump_output(self, proc: subprocess.Popen) -> None:
        try:
            if proc.stdout is None:
                return
            for raw in proc.stdout:
                line = raw.decode("utf-8", "replace").rstrip("\r\n")
                if line:
                    self._log(line)
        except Exception:
            pass
        code = proc.poll()
        if code is not None:
            self._log(f"процесс tun2proxy завершился, код {code}")

    def stop(self, timeout: float = 8.0) -> None:
        # Сначала возвращаем DNS: пока физический адаптер смотрит на TUN,
        # не хочется оставить машину без резолвера.
        if self._dns_hijacked or _read_dns_state():
            restore_dns_from_state()
            self._dns_hijacked = False
        with self._lock:
            proc = self._proc
            self._proc = None
        if proc is None:
            self._log("tun2proxy не запущен")
            return
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)
        except Exception as exc:
            logger.debug("tun2proxy stop error: %s", exc)
        self._log("tun2proxy остановлен")


# ══════════════════════════════════════════════════════════════════════
#  Помощник: сервер (в elevated-процессе)
# ══════════════════════════════════════════════════════════════════════

class _HelperConn:
    """Одно соединение с GUI: JSON-Lines, потокобезопасная отправка."""

    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._send_lock = threading.Lock()
        self.closed = False

    def send(self, obj: dict) -> None:
        if self.closed:
            return
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        try:
            with self._send_lock:
                self._sock.sendall(data)
        except OSError:
            self.closed = True

    def log(self, line: str) -> None:
        self.send({"type": "log", "line": line})

    def close(self) -> None:
        self.closed = True
        try:
            self._sock.close()
        except Exception:
            pass


def run_helper_server(port: int, token: str, idle_timeout: float = 0.0) -> None:
    """Сервер внутри elevated-процесса. Блокирует вызывающий поток."""
    # Если прошлый запуск завершился аварийно, DNS адаптера мог остаться
    # переключённым на TUN — возвращаем до любого старта.
    try:
        restore_dns_from_state()
    except Exception as exc:
        logger.debug("restore stale DNS failed: %s", exc)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", int(port)))
    except OSError as exc:
        logger.error("TUN helper cannot bind 127.0.0.1:%d (%s); другой экземпляр?", port, exc)
        return
    srv.listen(4)
    srv.settimeout(1.0)
    logger.info("TUN helper listening on 127.0.0.1:%d", port)

    last_client = time.time()
    try:
        while True:
            try:
                sock, _ = srv.accept()
            except socket.timeout:
                if idle_timeout and (time.time() - last_client) > idle_timeout:
                    logger.info("TUN helper idle timeout, exiting")
                    break
                continue
            last_client = time.time()
            conn = _HelperConn(sock)
            tun = TunProcess(on_log=conn.log)
            try:
                if not _serve_client(conn, token, tun):
                    break  # quit
            except Exception as exc:
                logger.warning("helper client error: %s", exc)
            finally:
                tun.stop()
                conn.close()
                # Отсчёт простоя начинается с момента отключения GUI.
                last_client = time.time()
    finally:
        try:
            srv.close()
        except Exception:
            pass


def _serve_client(conn: _HelperConn, token: str, tun: TunProcess) -> bool:
    """Обслуживает одно GUI-соединение. False = помощник должен выйти."""
    sock = conn._sock
    sock.settimeout(None)
    buf = bytearray()
    authenticated = False
    while not conn.closed:
        try:
            chunk = sock.recv(4096)
        except OSError:
            return True
        if not chunk:
            return True
        buf.extend(chunk)
        while b"\n" in buf:
            line, _, rest = buf.partition(b"\n")
            buf = bytearray(rest)
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line.decode("utf-8"))
            except Exception:
                conn.send({"type": "result", "id": None, "ok": False,
                           "error": "bad json"})
                continue
            if not authenticated:
                if str(req.get("token") or "") != token:
                    conn.send({"type": "hello", "id": req.get("id"), "ok": False,
                               "error": "bad token"})
                    return True
                authenticated = True
                conn.send({"type": "hello", "id": req.get("id"), "ok": True,
                           "admin": is_admin()})
                continue
            if not _handle_command(conn, req, tun):
                return False
    return True


def _handle_command(conn: _HelperConn, req: dict, tun: TunProcess) -> bool:
    cid = req.get("id")
    cmd = str(req.get("cmd") or "")

    def result(ok: bool, **extra) -> None:
        payload = {"type": "result", "id": cid, "ok": ok}
        payload.update(extra)
        conn.send(payload)

    try:
        if cmd == "ping":
            result(True, running=tun.is_running(), admin=is_admin())
        elif cmd == "start":
            args = req.get("args") or {}
            pid = tun.start(
                args.get("socks_host", "127.0.0.1"),
                int(args.get("socks_port", 8888)),
                mtu=int(args.get("mtu", DEFAULT_TUN_MTU)),
                dns_mode=str(args.get("dns_mode", DEFAULT_DNS_MODE)),
                bypass_ips=list(args.get("bypass_ips") or []),
                verbosity=str(args.get("verbosity", "info")),
                tun_name=str(args.get("tun_name") or ""),
                dns_hijack=bool(args.get("dns_hijack", True)),
                physical_alias=str(args.get("physical_alias") or ""),
                physical_ip=str(args.get("physical_ip") or ""),
            )
            result(True, pid=pid)
        elif cmd == "stop":
            tun.stop()
            result(True)
        elif cmd == "quit":
            result(True)
            return False
        else:
            result(False, error=f"unknown cmd {cmd!r}")
    except Exception as exc:
        result(False, error=f"{type(exc).__name__}: {exc}")
    return True


# ══════════════════════════════════════════════════════════════════════
#  Помощник: клиент (в GUI-процессе)
# ══════════════════════════════════════════════════════════════════════

def _python_for_helper() -> tuple[str, str]:
    """(executable, вид запуска) для elevated-помощника."""
    if getattr(sys, "frozen", False):
        return sys.executable, "frozen"
    exe = Path(sys.executable)
    pythonw = exe.with_name("pythonw.exe")
    return (str(pythonw if pythonw.is_file() else exe), "script")


def _ps_quote(arg: str) -> str:
    return '"' + str(arg).replace('"', r'\"') + '"'


def launch_elevated_helper(port: int, token: str,
                           idle_timeout: float = HELPER_IDLE_TIMEOUT) -> None:
    """Просит UAC и запускает помощник. Бросает при отказе/ошибке.

    idle_timeout — сколько секунд помощник живёт после отключения GUI.
    Так повторный запуск приложения в этом окне не требует нового UAC,
    но забытый elevated-процесс не остаётся навсегда.
    """
    if not IS_WINDOWS:
        raise RuntimeError("TUN helper is Windows-only")
    exe, kind = _python_for_helper()
    tail = f" --idle-timeout {int(idle_timeout)}" if idle_timeout > 0 else ""
    if kind == "frozen":
        params = f"--tun-helper --port {int(port)} --token {_ps_quote(token)}{tail}"
    else:
        helper_py = Path(__file__).resolve().parent / "vpn_helper.py"
        params = (f"{_ps_quote(str(helper_py))} --port {int(port)} "
                  f"--token {_ps_quote(token)}{tail}")
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", exe, params, str(Path.cwd()), 0)
    if int(rc) <= 32:
        raise PermissionError(
            f"не удалось запустить повышенный помощник (ShellExecute={rc}). "
            "Запрос UAC отклонён?")


class TunHelperClient:
    """Клиент elevated-помощника: один UAC на запуск приложения.

    Порт и токен можно переиспользовать между запусками GUI (передаются
    снаружи) — тогда уже работающий помощник подхватывается без UAC.
    """

    def __init__(self, on_log: Optional[Callable[[str], None]] = None):
        self._on_log = on_log
        self._sock: Optional[socket.socket] = None
        self._port: Optional[int] = None
        self._token: Optional[str] = None
        self._id = 0
        self._pending: dict[int, threading.Event] = {}
        self._results: dict[int, dict] = {}
        self._reader: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    # ── логи ──

    def _log(self, line: str) -> None:
        if self._on_log:
            try:
                self._on_log(line)
            except Exception:
                pass

    # ── соединение ──

    def is_connected(self) -> bool:
        return self._sock is not None

    def matches(self, port: int, token: str) -> bool:
        """Подходит ли текущее соединение под эти порт/токен."""
        return (self._sock is not None and self._port == int(port)
                and self._token == str(token))

    def connect(self, port: int, token: str, wait: float = 25.0,
                allow_launch: bool = True) -> bool:
        """Подключается к помощнику; при необходимости поднимает его (UAC)."""
        self._port = int(port)
        self._token = str(token)
        if self.matches(port, token):
            # Уже подключены теми же портом/токеном: второе соединение
            # заняло бы accept-очередь помощника, а старое осталось бы
            # висеть в _serve_client.
            return True
        if self._sock is not None:
            self._close()
        if self._try_connect():
            return True
        if not allow_launch:
            return False
        self._log("Запрос прав администратора для TUN-режима (UAC)…")
        try:
            launch_elevated_helper(self._port, self._token)
        except Exception as exc:
            self._log(f"Не удалось запустить помощник: {exc}")
            return False
        deadline = time.time() + wait
        while time.time() < deadline:
            if self._try_connect():
                return True
            time.sleep(0.5)
        self._log("Помощник не поднялся за отведённое время.")
        return False

    def _try_connect(self) -> bool:
        try:
            s = socket.create_connection(("127.0.0.1", int(self._port)), timeout=2.0)
        except OSError:
            return False
        # Сокет должен быть блокирующим: таймаут на recv убил бы читающий
        # поток через 8 секунд простоя. Ограничиваем только ожидание ответа.
        try:
            s.settimeout(None)
        except OSError:
            pass
        self._sock = s
        self._reader = threading.Thread(target=self._read_loop, args=(s,), daemon=True)
        self._reader.start()
        if self._handshake():
            return True
        self._close()
        return False

    def _handshake(self) -> bool:
        try:
            resp = self._request("__hello__", token=self._token)
        except Exception:
            return False
        return bool(resp and resp.get("ok"))
    def _close(self) -> None:
        s = self._sock
        self._sock = None
        if s is not None:
            try:
                s.close()
            except Exception:
                pass

    # ── RPC ──

    def _read_loop(self, sock: socket.socket) -> None:
        buf = bytearray()
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                buf.extend(chunk)
                while b"\n" in buf:
                    line, _, rest = buf.partition(b"\n")
                    buf = bytearray(rest)
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        msg = json.loads(line.decode("utf-8"))
                    except Exception:
                        continue
                    self._dispatch(msg)
        except OSError:
            pass
        finally:
            with self._lock:
                for ev in self._pending.values():
                    ev.set()

    def _dispatch(self, msg: dict) -> None:
        if msg.get("type") == "log":
            self._log(str(msg.get("line") or ""))
            return
        cid = msg.get("id")
        with self._lock:
            self._results[cid] = msg
            ev = self._pending.get(cid)
        if ev is not None:
            ev.set()

    def _request(self, cmd: str, *, token: Optional[str] = None,
                 args: Optional[dict] = None, timeout: float = 30.0) -> dict:
        sock = self._sock
        if sock is None:
            raise RuntimeError("helper not connected")
        with self._lock:
            self._id += 1
            cid = self._id
            ev = threading.Event()
            self._pending[cid] = ev
        payload: dict = {"id": cid, "cmd": cmd}
        if token is not None:
            payload["token"] = token
        if args is not None:
            payload["args"] = args
        try:
            sock.sendall((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        except OSError as exc:
            with self._lock:
                self._pending.pop(cid, None)
            raise RuntimeError(f"helper write failed: {exc}") from exc
        got = ev.wait(timeout)
        with self._lock:
            self._pending.pop(cid, None)
            result = self._results.pop(cid, None)
        if not got or result is None:
            raise TimeoutError(f"helper no response for {cmd}")
        return result

    # ── команды ──

    def start_tun(self, socks_host: str, socks_port: int, *,
                  mtu: int = DEFAULT_TUN_MTU, dns_mode: str = DEFAULT_DNS_MODE,
                  bypass_ips: Optional[list[str]] = None,
                  verbosity: str = "info", tun_name: str = "",
                  dns_hijack: bool = True, physical_alias: str = "",
                  physical_ip: str = "") -> dict:
        return self._request("start", args={
            "socks_host": socks_host, "socks_port": socks_port,
            "mtu": mtu, "dns_mode": dns_mode,
            "bypass_ips": list(bypass_ips or []), "verbosity": verbosity,
            "tun_name": tun_name, "dns_hijack": bool(dns_hijack),
            "physical_alias": physical_alias, "physical_ip": physical_ip,
        })

    def stop_tun(self) -> dict:
        return self._request("stop", timeout=15.0)

    def ping(self) -> dict:
        return self._request("ping")

    def quit(self) -> None:
        try:
            self._request("quit", timeout=5.0)
        except Exception:
            pass
        self._close()
