"""Проверка подключения профиля (desktop-аналог Android `test_profile`).

Поднимает временный туннель с настройками профиля, открывает сессию к
`api.ipify.org:80` (fallback `ifconfig.me:80`) через выбранный маршрут и
возвращает задержку, exit IP и фактическую цепочку узлов.

Работает и без запущенного VPN: проверка изолирована своим туннелем.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time

from tunnel import ClientTunnel

logger = logging.getLogger("vpn-test")

TEST_TARGET = ("api.ipify.org", 80)
TEST_TARGET_FALLBACK = ("ifconfig.me", 80)


class _ProbeSink:
    """Подменяет StreamWriter локального клиента и собирает ответ туннеля."""

    def __init__(self):
        self.data = bytearray()
        self.first_byte_at = None
        self.done = asyncio.Event()

    def write(self, data: bytes, *args, **kwargs):
        if not data:
            return
        if self.first_byte_at is None:
            self.first_byte_at = time.monotonic()
        self.data.extend(data)
        text = self.data.decode("latin-1", "ignore")
        head, sep, body = text.partition("\r\n\r\n")
        if sep and "content-length:" in head.lower():
            try:
                length = int(head.lower().split("content-length:", 1)[1]
                            .split("\r\n", 1)[0].strip())
                if len(body) >= length:
                    self.done.set()
            except Exception:
                pass

    async def drain(self):
        return None

    def close(self):
        self.done.set()

    def get_extra_info(self, name, default=None):
        return default


def _is_ip(value: str) -> bool:
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except OSError:
            continue
    return False


def _node_label(cfg: dict, url: str) -> str:
    if not url:
        return "auto"
    target = str(url).rstrip("/")
    for node in cfg.get("nodes") or []:
        if str(node.get("url") or "").rstrip("/") == target:
            return str(node.get("id") or target)
    return target


def _route_label(cfg: dict, route: tuple) -> str:
    if not route:
        return "auto"
    if route[0] == "direct":
        return "direct"
    ids = list(route[2]) if len(route) > 2 and route[2] else []
    if ids:
        return " → ".join(str(x) for x in ids)
    return _node_label(cfg, route[1] or "")


def _parse_http(raw: bytes):
    text = raw.decode("utf-8", "replace")
    head, _sep, body = text.partition("\r\n\r\n")
    status = 0
    parts = head.split("\r\n", 1)[0].split() if head else []
    if len(parts) >= 2 and parts[1].isdigit():
        status = int(parts[1])
    return status, body.strip()


def _extract_ip(body: str) -> str:
    for line in body.replace("\r", "\n").split("\n"):
        candidate = line.strip().strip('"').strip()
        if not candidate:
            continue
        if _is_ip(candidate):
            return candidate
        for key in ('"ip"', '"query"', '"origin"'):
            idx = candidate.find(key)
            if idx < 0:
                continue
            rest = candidate[idx + len(key):].lstrip(": ").lstrip('"')
            value = rest.split('"', 1)[0].strip()
            if _is_ip(value):
                return value
    return ""


async def _probe_target(tunnel: ClientTunnel, host: str, port: int, timeout: float) -> dict:
    route = tunnel.route_for(host)
    result = {
        "ok": False,
        "latency_ms": 0,
        "exit_ip": "",
        "route": _route_label(tunnel.cfg, route),
        "mode": route[0],
        "error": "",
    }
    if route[0] == "error":
        result["error"] = route[4] if len(route) > 4 else "route unavailable"
        return result

    request = (
        f"GET / HTTP/1.0\r\nHost: {host}\r\n"
        "Accept: text/plain\r\nUser-Agent: vpn-client/1.0\r\n"
        "Connection: close\r\n\r\n"
    ).encode()

    started = time.monotonic()
    if route[0] == "direct":
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        try:
            writer.write(request)
            await writer.drain()
            raw = await asyncio.wait_for(reader.read(), timeout=timeout)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        result["latency_ms"] = int((time.monotonic() - started) * 1000)
        status, body = _parse_http(raw)
        ip = _extract_ip(body)
        if status and ip:
            result.update(ok=True, exit_ip=ip)
        else:
            result["error"] = f"direct: HTTP {status or '?'}, exit IP not found"
        return result

    sink = _ProbeSink()
    sid = await tunnel.register_session(
        sink, host, port,
        server_base=route[1],
        route=route[2] if len(route) > 2 else (),
    )
    await tunnel.feed_outgoing(sid, request)
    try:
        await asyncio.wait_for(sink.done.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        pass

    latency = ((sink.first_byte_at or time.monotonic()) - started) * 1000
    result["latency_ms"] = max(0, int(latency))
    status, body = _parse_http(bytes(sink.data))
    ip = _extract_ip(body)
    if status and ip:
        result.update(ok=True, exit_ip=ip)
    elif not sink.data:
        result["error"] = "no response (timeout or route unreachable)"
    elif status:
        result["error"] = f"HTTP {status}, but exit IP not found"
    else:
        result["error"] = "invalid HTTP response"
    return result


def _prepare_test_config(cfg: dict) -> dict:
    """Готовит копию конфига для проверочного туннеля.

    - если есть снимок `nodes`, подписка не скачивается повторно;
    - локальные действия профиля (`routing`) важнее действий подписки;
    - обычные интервалы опроса и idle/DNS для теста не нужны.
    """
    import copy

    cfg = copy.deepcopy(cfg)
    if cfg.get("nodes"):
        cfg.pop("subscription", None)

    routing = cfg.get("routing") or {}
    actions: dict = {}
    for key in ("ru", "non_ru", "private"):
        value = str(routing.get(key) or "").strip()
        if not value:
            continue
        if value.lower() == "direct":
            actions[key] = {"direct": True}
        else:
            actions[key] = {"route": value}
    cfg["split_routing"] = {
        "enabled": bool(routing.get("enabled", False)),
        "default": "non_ru",
        "actions": actions,
        # Правила классификации берём из подписки, если они уже загружены.
        "rules": (cfg.get("split_routing") or {}).get("rules") or {},
    }

    client = cfg.setdefault("client", {})
    client["poll_interval_ms"] = min(int(client.get("poll_interval_ms", 100) or 100), 100)
    client["poll_jitter_ms"] = min(int(client.get("poll_jitter_ms", 5) or 5), 10)
    (client.get("idle_timeout") or {}).setdefault("enabled", False)
    client["idle_timeout"] = {"enabled": False, "seconds": client.get("idle_timeout", {}).get("seconds", 300)}
    client["dns_relay"] = {"enabled": False,
                           "bind_host": client.get("dns_relay", {}).get("bind_host", "127.0.0.1"),
                           "bind_port": client.get("dns_relay", {}).get("bind_port", 5353)}
    return cfg


async def probe_profile_async(cfg: dict, timeout: float = 15.0) -> dict:
    """Проверяет подключение по готовому конфигу движка.

    Аналог Android `TestConfig.build`: если в профиле уже есть снимок
    `nodes`, подписка повторно не скачивается; интервалы опроса и
    idle/DNS принудительно отключаются для быстрой проверки.
    """
    cfg = _prepare_test_config(cfg)
    tunnel = None
    poll_task = None
    try:
        tunnel = ClientTunnel(cfg)
        tunnel.set_log_callback(lambda _msg: None)
        poll_task = asyncio.create_task(tunnel.poll_loop())
        last_error = ""
        last_result = None
        per_try = max(4.0, timeout / 2.0)
        for host, port in (TEST_TARGET, TEST_TARGET_FALLBACK):
            try:
                result = await _probe_target(tunnel, host, port, per_try)
            except Exception as exc:
                result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
            if result.get("ok"):
                return result
            last_result = result
            last_error = str(result.get("error") or "no response")
            if "route" in last_error.lower() or "unavailable" in last_error.lower():
                break
        if last_result:
            last_result["ok"] = False
            last_result["error"] = last_error
            return last_result
        return {"ok": False, "error": last_error, "route": "",
                "exit_ip": "", "latency_ms": 0, "mode": ""}
    finally:
        if tunnel is not None:
            tunnel._stop = True
        if poll_task is not None:
            poll_task.cancel()
            try:
                await poll_task
            except BaseException:
                pass
        if tunnel is not None:
            try:
                await tunnel.http.aclose()
            except Exception:
                pass


def test_profile(cfg: dict, timeout: float = 15.0) -> dict:
    """Синхронная обёртка для вызова из фонового потока UI."""
    try:
        return asyncio.run(probe_profile_async(cfg, max(3.0, float(timeout))))
    except Exception as exc:
        return {"ok": False, "latency_ms": 0, "exit_ip": "", "route": "",
                "mode": "", "error": f"{type(exc).__name__}: {exc}"}
