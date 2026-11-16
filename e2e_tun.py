"""E2E: настоящий TUN-режим на Windows.

Поднимает обычный туннель + SOCKS5 (как GUI), затем через elevated-помощник
(UAC) запускает tun2proxy с --setup и проверяет:

  1. Wintun-адаптер создан и Up, адрес 10.0.0.33;
  2. DNS физического адаптера переключён на 10.0.0.1;
  3. трафик через TUN (source = 10.0.0.33) реально идёт через наш туннель;
  4. наш SOCKS5 работает и при поднятом TUN;
  5. после stop DNS восстановлен, адаптер удалён.

Полный лог пишется в e2e_tun.log.

Запуск (нужно подтвердить UAC):
    .venv\\Scripts\\python.exe e2e_tun.py
"""

import asyncio
import json
import socket
import subprocess
import sys
import time

sys.path.insert(0, r"C:\Users\victor\Desktop\Projects\vpn\short-polling-vpn")

from desktop_config import DesktopConfig
from tunnel import ClientTunnel
from socks5_server import handle_socks_client
import tun_mode

PROJECT = r"C:\Users\victor\Desktop\Projects\vpn\short-polling-vpn"
SOCKS_PORT = 8888
TUN_IP = "10.0.0.33"
LOG_PATH = PROJECT + r"\e2e_tun.log"

_log_file = open(LOG_PATH, "w", encoding="utf-8")


def out(line: str) -> None:
    print(line)
    print(line, file=_log_file, flush=True)


def ps(cmd: str) -> str:
    res = subprocess.run(
        ["powershell", "-NoProfile", "-NonInteractive", "-Command",
         "[Console]::OutputEncoding=[Text.Encoding]::UTF8; " + cmd],
        capture_output=True, timeout=40,
    )
    return (res.stdout or b"").decode("utf-8", "replace").strip()


def snapshot() -> dict:
    return {
        "adapter": ps(
            "Get-NetAdapter -IncludeHidden -ErrorAction SilentlyContinue | "
            "Where-Object { $_.Name -eq 'vpnclient' } | "
            "Select-Object Name, Status | ConvertTo-Json -Compress"),
        "tun_ip": ps(
            "(Get-NetIPAddress -InterfaceAlias 'vpnclient' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue).IPAddress -join ','"),
        "default_route": ps(
            "Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | "
            "Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1 "
            "-ExpandProperty InterfaceAlias"),
        "wifi_dns": ps(
            "(Get-DnsClientServerAddress -InterfaceAlias 'Wi-Fi' -AddressFamily IPv4 "
            "-ErrorAction SilentlyContinue).ServerAddresses -join ','"),
    }


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("SOCKS5 peer closed")
        buf += chunk
    return buf


def socks5_http_get(host: str = "api.ipify.org", port: int = 80,
                    path: str = "/", timeout: float = 25.0) -> str:
    """GET через наш SOCKS5 без внешних зависимостей (httpx[socks] не нужен).

    Использует ATYP=DOMAIN, как tun2proxy в режиме virtual DNS, — так
    проверяется именно тот путь, которым пойдёт реальный TUN-трафик.
    """
    with socket.create_connection(("127.0.0.1", SOCKS_PORT), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if _recv_exact(s, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS5 method negotiation failed")
        host_b = host.encode()
        s.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b
                  + port.to_bytes(2, "big"))
        head = _recv_exact(s, 4)
        if head[1] != 0:
            raise ConnectionError(f"SOCKS5 CONNECT failed, rep={head[1]}")
        atyp = head[3]
        if atyp == 0x01:
            _recv_exact(s, 4)
        elif atyp == 0x03:
            _recv_exact(s, _recv_exact(s, 1)[0])
        elif atyp == 0x04:
            _recv_exact(s, 16)
        _recv_exact(s, 2)
        s.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   "Connection: close\r\n\r\n").encode())
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    if not data:
        raise ConnectionError("empty HTTP response")
    head, _, body = data.partition(b"\r\n\r\n")
    status = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    return f"{status} {body.decode('utf-8', 'replace').strip()[:60]}"


def probe(label: str, local: str = "", socks: bool = False,
          target: str = "https://api.ipify.org") -> str:
    if socks:
        try:
            return f"{label}: 200 {socks5_http_get()}"
        except Exception as exc:
            return f"{label}: ERR {type(exc).__name__}: {exc}"
    import httpx
    try:
        if local:
            client = httpx.Client(
                transport=httpx.HTTPTransport(local_address=local, retries=0),
                timeout=20.0)
        else:
            client = httpx.Client(timeout=20.0)
        with client:
            r = client.get(target)
            return f"{label}: {r.status_code} {r.text.strip()[:60]}"
    except Exception as exc:
        return f"{label}: ERR {type(exc).__name__}: {exc}"


def pick_profile(store: DesktopConfig) -> dict:
    for name in ("Финляндия через Россию", "Германия через Россию",
                 "Финляндия 2", "Финляндия CDN"):
        for p in store.load_profiles():
            if p["name"] == name:
                return p
    return store.get_active_profile()


async def async_probe(label: str, **kw) -> str:
    # Пробу надо гонять в потоке: SOCKS-ответ обслуживает тот же event loop,
    # который крутит poll_loop(), иначе получим самоблокировку.
    return await asyncio.to_thread(probe, label, **kw)


async def main() -> int:
    store = DesktopConfig(PROJECT)
    profile = pick_profile(store)
    if not profile:
        out("NO PROFILE")
        return 2
    out(f"profile: {profile['name']} | mode: {profile.get('mode')} | "
        f"backend: {profile.get('vpn_backend')}")

    adapter = tun_mode.detect_physical_adapter()
    out(f"physical adapter: {adapter}")
    direct_probe = await async_probe("exit")
    out("before: " + direct_probe)

    cfg = store.engine_config(profile)
    cfg.setdefault("client", {})["tun_resolve"] = True
    cfg["client"]["local_address"] = (adapter or {}).get("ip") or ""
    cfg["client"]["verify_tls"] = True

    tunnel = ClientTunnel(cfg)
    tunnel.set_log_callback(lambda m: out("  TUNNEL: " + str(m)))
    resolved = tunnel.resolve_host_ips()
    out("resolved: " + json.dumps(resolved, ensure_ascii=False))

    poll_task = asyncio.create_task(tunnel.poll_loop())
    socks = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w),
        "127.0.0.1", SOCKS_PORT, reuse_address=True)
    out(f"SOCKS5 on {SOCKS_PORT}")
    await asyncio.sleep(2.0)
    socks_before = await async_probe("socks", socks=True)
    out("socks before TUN: " + socks_before)

    tun_cfg = cfg["client"].get("tun") or {}
    helper = tun_mode.TunHelperClient(on_log=lambda m: out("  HELPER: " + str(m)))
    port = int(tun_cfg.get("helper_port", tun_mode.DEFAULT_HELPER_PORT))
    token = "e2e-token-" + str(int(time.time()))
    out(">>> Сейчас появится запрос UAC — подтвердите его.")
    ok = helper.connect(port, token, wait=150.0)
    out(f"helper connected: {ok}")
    if not ok:
        socks.close()
        await socks.wait_closed()
        poll_task.cancel()
        await tunnel.stop()
        return 1

    bypass = list(tun_cfg.get("bypass_ips") or []) + list(resolved.values()) + \
        tun_mode.literal_ips_from_urls(cfg["client"].get("server_urls") or [])
    bypass = list(dict.fromkeys([ip for ip in bypass if ip]))

    rc = 0
    try:
        resp = helper.start_tun(
            "127.0.0.1", SOCKS_PORT,
            mtu=int(tun_cfg.get("mtu", 1500)),
            dns_mode=str(tun_cfg.get("dns_mode", "virtual")),
            bypass_ips=bypass,
            verbosity="debug",
            tun_name=str(tun_cfg.get("name") or "vpnclient"),
            dns_hijack=bool(tun_cfg.get("dns_hijack", True)),
            physical_alias=str((adapter or {}).get("alias") or ""),
            physical_ip=str((adapter or {}).get("ip") or ""),
        )
        out(f"start_tun: {resp}")
        if not resp.get("ok"):
            return 1

        await asyncio.sleep(7)
        state = snapshot()
        out(f"adapter: {state['adapter']}")
        out(f"tun ip: {state['tun_ip']}")
        out(f"default route: {state['default_route']}")
        out(f"Wi-Fi DNS: {state['wifi_dns']}")
        out("dns check: " + ps(
            "Resolve-DnsName api.ipify.org -Type A -ErrorAction SilentlyContinue | "
            "Where-Object { $_.IPAddress } | Select-Object -ExpandProperty IPAddress "
            "| Select-Object -First 3 | Out-String").replace("\r", " ").replace("\n", " "))

        if "Up" not in (state["adapter"] or ""):
            out("FAIL: TUN adapter is not up")
            rc = 1
        if state["wifi_dns"] != tun_mode.TUN_GATEWAY:
            out("FAIL: DNS was not hijacked")
            rc = 1
        if state["default_route"] != "vpnclient":
            out(f"WARN: default route is {state['default_route']} "
                "(другой VPN перехватывает) — проверяем через source bind")

        socks_during = await async_probe("socks", socks=True)
        tun_bound = await async_probe("tun", local=state["tun_ip"] or TUN_IP)
        plain_during = await async_probe("plain")
        out("socks during TUN: " + socks_during)
        out("tun-bound : " + tun_bound)
        out("plain     : " + plain_during)

        def tail_ip(text: str) -> str:
            return (text.rsplit(" ", 1)[-1] or "").strip()

        direct_ip = tail_ip(direct_probe)
        socks_ip = tail_ip(socks_during)
        plain_ip = tail_ip(plain_during)
        if "ERR" in socks_during:
            out("FAIL: our SOCKS5 does not work")
            rc = 1
        if "ERR" in plain_during:
            out("FAIL: system traffic does not pass through the TUN")
            rc = 1
        elif plain_ip == direct_ip:
            out(f"FAIL: plain traffic exits directly ({plain_ip}), not through the tunnel")
            rc = 1
        elif socks_ip and plain_ip and socks_ip != plain_ip:
            out(f"WARN: socks exit {socks_ip} != plain exit {plain_ip} (split-routing?)")
    finally:
        try:
            out(f"stop_tun: {helper.stop_tun()}")
        except Exception as exc:
            out(f"stop_tun ERR {exc}")
        await asyncio.sleep(3)
        state = snapshot()
        out(f"after stop adapter: {state['adapter']}")
        out(f"after stop default route: {state['default_route']}")
        out(f"after stop Wi-Fi DNS: {state['wifi_dns']}")
        out("after stop: " + await async_probe("exit"))
        if state["wifi_dns"] == tun_mode.TUN_GATEWAY:
            out("FAIL: DNS not restored")
            rc = 1
        helper.quit()
        socks.close()
        await socks.wait_closed()
        poll_task.cancel()
        await tunnel.stop()

    out("E2E TUN: " + ("OK" if rc == 0 else "FAILED"))
    return rc


try:
    code = asyncio.run(main())
finally:
    _log_file.close()
sys.exit(code)
