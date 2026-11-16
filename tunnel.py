"""
Общий туннель для VPN-клиентов.

Содержит:
  - ClientSession — состояние одной локальной TCP-сессии
  - ClientTunnel — базовый класс туннеля (сессии, пуллинг, DNS relay, URL selection)

Используется desktop_client.py, client.py и android proxy_engine.py.
"""

import asyncio
import base64
import logging
import os
import random
import struct
import time
import uuid
from collections import defaultdict
from typing import Optional

import httpx

from protocol import (
    Frame, FLAG_NEW, FLAG_DATA, FLAG_FIN, FLAG_DNS,
    PROTO_VERSION, RESP_STREAM_MAGIC,
    pack_frames, unpack_frames, new_session_id, pad_frames,
)
from crypto_utils import (
    derive_key, derive_hmac_key, encrypt, decrypt, sign,
    b64u_encode, b64u_decode,
)
from cdn_paths import random_cdn_path
from subscription import load_and_apply, load_subscription, apply_subscription
from split_routing import SplitRouter

logger = logging.getLogger("vpn-tunnel")


class ClientSession:
    """Состояние одной локальной TCP-сессии (принятой по SOCKS5)."""

    def __init__(self, session_id: bytes, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.writer = writer
        self.seq = 0
        self.outgoing = bytearray()
        self.pending_new = None
        self.closed = False
        self.fin_sent = False
        # URL входа, за которым закреплена сессия. Все кадры этой сессии
        # должны идти только туда, иначе сервер не найдёт своё состояние.
        self.server_base: str = ""
        # Полная цепочка node_id (entry, relay..., exit) для relay-маршрута.
        self.route: tuple[str, ...] = ()

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


class ClientTunnel:
    """Базовый класс туннеля для VPN-клиента.

    Поддерживает:
      - Мультиплексирование сессий через HTTP polling
      - Случайные CDN-пути для маскировки трафика
      - Синхронизацию времени по Date-заголовку
      - DNS relay
      - Выбор сервера (random/round-robin) с карантином при ошибках
    """

    def __init__(self, cfg: dict):
        cfg = load_and_apply(cfg)
        self.cfg = cfg
        client_cfg = cfg["client"]
        sec_cfg = cfg["security"]

        self.client_id = os.urandom(16)
        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        self.all_server_urls = [u.rstrip("/") for u in urls if u]
        disabled = client_cfg.get("disabled_urls") or []
        self.disabled_urls = {u.rstrip("/") for u in disabled if u}
        self.server_urls = [u for u in self.all_server_urls if u not in self.disabled_urls]
        self.server_base = (self.server_urls[0] if self.server_urls else
                            (self.all_server_urls[0] if self.all_server_urls
                             else client_cfg.get("server_url", "").rstrip("/")))
        self._no_url_warned = False
        self.server_selector = str(client_cfg.get("server_selector", "random")).lower()
        self._rr_index = 0
        self._url_failures = {}
        self._url_cooldown_until = {}
        self.url_fail_limit = max(1, int(client_cfg.get("url_fail_limit", 3)))
        self.url_cooldown_seconds = max(1, int(client_cfg.get("url_cooldown_seconds", 60)))
        self._all_q_logged = False
        self.poll_path = client_cfg.get("poll_path", "/poll")
        self.poll_interval_ms = int(client_cfg.get("poll_interval_ms", 200))
        self.poll_jitter_ms = int(client_cfg.get("poll_jitter_ms", 50))
        self.pad_polls = bool(client_cfg.get("pad_polls", True))
        self.max_chunk_bytes = int(client_cfg.get("max_chunk_bytes", 4096))
        self.poll_method = client_cfg.get("poll_method", "POST").upper()
        self.poll_data_in = client_cfg.get("poll_data_in", "body")
        self.host_header = client_cfg.get("host_header") or None
        verify_tls = client_cfg.get("verify_tls", True)
        trust_env = client_cfg.get("trust_env_proxy", False)

        # Per-user режим: пользователь и устройство из подписки. Ключи в этом
        # режиме выводятся из секрета пользователя, поэтому общий PSK может
        # быть пустым/плейсхолдером — не трогаем его раньше времени.
        user_cfg = cfg.get("user") or {}
        self.user_id = str(user_cfg.get("uuid") or "").strip()
        self.device_id = str(user_cfg.get("device_id") or "").strip()
        user_secret = user_cfg.get("secret") or ""
        if self.user_id and user_secret:
            if not self.device_id:
                self.device_id = str(uuid.uuid4())
            secret = b64u_decode(str(user_secret))
            psk_b64 = base64.b64encode(secret).decode()
            self.enc_key = derive_key(psk_b64)
            self.hmac_key = derive_hmac_key(psk_b64)
        else:
            self.user_id = ""
            self.device_id = ""
            psk = str(sec_cfg.get("psk") or "").strip()
            try:
                self.enc_key = derive_key(psk)
                self.hmac_key = derive_hmac_key(psk)
            except Exception as exc:
                raise ValueError(
                    "invalid security.psk (must be base64 of 32 bytes) and no "
                    f"per-user secret in subscription: {exc}"
                ) from exc

        idle_cfg = client_cfg.get("idle_timeout", {})
        self.idle_timeout_enabled = idle_cfg.get("enabled", False)
        self.idle_timeout_seconds = int(idle_cfg.get("seconds", 300))
        self._last_activity = time.monotonic()
        self._idle_logged = False

        self.sessions: dict = {}
        self.lock = asyncio.Lock()
        # Короткий connect timeout: недоступный узел не должен надолго
        # задерживать poll-цикл (read timeout длинный для long-poll).
        self.http = httpx.AsyncClient(
            http2=True, verify=verify_tls, trust_env=trust_env,
            timeout=httpx.Timeout(15.0, connect=4.0))
        self._stop = False

        # Смещение времени своё для каждого URL: часы серверов могут
        # расходиться, и общий offset ломал бы HMAC при мультисервере.
        self._time_offsets: dict[str, int] = {}
        self.split_router = SplitRouter(cfg)

        sub_cfg = cfg.get("subscription") or {}
        self._sub_source = sub_cfg.get("url") or sub_cfg.get("file") or ""
        self._sub_interval = max(3600, int(sub_cfg.get("auto_update_hours", 6)) * 3600)
        self._sub_task: asyncio.Task | None = None

        dns_cfg = client_cfg.get("dns_relay", {})
        self.dns_relay_enabled = dns_cfg.get("enabled", False)
        self.dns_bind_host = dns_cfg.get("bind_host", "127.0.0.1")
        self.dns_bind_port = int(dns_cfg.get("bind_port", 5353))
        self._dns_pending: dict = {}
        self._dns_outbox: list = []
        self._fin_outbox: list = []
        self._dns_transport = None
        self._dns_protocol = None
        self._dns_task = None
        self._poll_count = 0
        self._health_inflight: set[str] = set()

        self._on_log = None

        logger.info("client_id=%s", self.client_id.hex())

    def set_log_callback(self, cb):
        """Подписывает GUI/вызывающий код на сообщения туннеля."""
        self._on_log = cb

    def log(self, msg: str):
        if self._on_log:
            self._on_log(msg)
        else:
            logger.info(msg)

    def apply_config(self, cfg: dict):
        """Применяет новые настройки из config.yaml без перезапуска.

        Обновляет параметры polling, server URLs, idle timeout и т.д.
        Ключи шифрования (psk), порты и bind-адреса НЕ перезапускаются.
        """
        client_cfg = cfg["client"]

        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        new_all = [u.rstrip("/") for u in urls if u]
        disabled = client_cfg.get("disabled_urls") or []
        new_disabled = {u.rstrip("/") for u in disabled if u}
        new_urls = [u for u in new_all if u not in new_disabled]
        if new_urls != self.server_urls or new_disabled != self.disabled_urls:
            logger.info("Config reload: server_urls changed")
            self.all_server_urls = new_all
            self.disabled_urls = new_disabled
            self.server_urls = new_urls
            self.server_base = new_urls[0] if new_urls else self.server_base
            self._url_failures.clear()
            self._url_cooldown_until.clear()
            self._no_url_warned = False
            self._time_offsets.clear()

        self.server_selector = str(client_cfg.get("server_selector", "random")).lower()
        self.url_fail_limit = max(1, int(client_cfg.get("url_fail_limit", 3)))
        self.url_cooldown_seconds = max(1, int(client_cfg.get("url_cooldown_seconds", 60)))
        self._all_q_logged = False
        self.poll_path = client_cfg.get("poll_path", "/poll")
        self.poll_interval_ms = int(client_cfg.get("poll_interval_ms", 200))
        self.poll_jitter_ms = int(client_cfg.get("poll_jitter_ms", 50))
        self.pad_polls = bool(client_cfg.get("pad_polls", True))
        self.max_chunk_bytes = int(client_cfg.get("max_chunk_bytes", 4096))
        self.poll_method = client_cfg.get("poll_method", "POST").upper()
        self.poll_data_in = client_cfg.get("poll_data_in", "body")
        self.host_header = client_cfg.get("host_header") or None

        idle_cfg = client_cfg.get("idle_timeout", {})
        self.idle_timeout_enabled = idle_cfg.get("enabled", False)
        self.idle_timeout_seconds = int(idle_cfg.get("seconds", 300))

    # ── Сессии ──

    def route_for(self, host: str):
        """Возвращает (mode, base_url, category) для split-routing."""
        return self.split_router.route_for(host, set(self._available_urls()))

    async def register_session(self, writer: asyncio.StreamWriter, host: str, port: int,
                               server_base: str | None = None,
                               route: tuple[str, ...] = ()) -> bytes:
        sid = new_session_id()
        sess = ClientSession(sid, writer)
        # Закрепляем сессию за входным URL на всё время жизни.
        sess.server_base = server_base or self._pick_server_base() or self.server_base
        sess.route = tuple(route or ())
        frame = Frame.new_frame(sid, sess.next_seq(), host, port)
        sess.pending_new = frame
        async with self.lock:
            self.sessions[sid] = sess
        self._last_activity = time.monotonic()
        logger.debug("new session %s -> %s:%s", sid.hex()[:8], host, port)
        return sid

    async def feed_outgoing(self, sid: bytes, data: bytes):
        async with self.lock:
            sess = self.sessions.get(sid)
            if sess:
                sess.outgoing.extend(data)
        self._last_activity = time.monotonic()

    async def mark_closed(self, sid: bytes):
        async with self.lock:
            sess = self.sessions.get(sid)
            if sess:
                sess.closed = True

    # ── DNS relay ──

    def _start_dns_relay(self):
        if not self.dns_relay_enabled:
            return
        loop = asyncio.get_event_loop()

        class DnsUdpProtocol(asyncio.DatagramProtocol):
            def __init__(self, owner):
                self.owner = owner
            def datagram_received(self, data, addr):
                asyncio.create_task(self.owner._handle_dns_query(data, addr))
            def error_received(self, exc):
                logger.warning("dns relay udp error: %s", exc)

        self._dns_protocol = DnsUdpProtocol(self)

        async def _bind():
            try:
                self._dns_transport, _ = await loop.create_datagram_endpoint(
                    lambda: self._dns_protocol,
                    local_addr=(self.dns_bind_host, self.dns_bind_port),
                )
                logger.info("DNS relay listening on %s:%d", self.dns_bind_host, self.dns_bind_port)
            except Exception as e:
                logger.error("failed to start DNS relay: %s", e)
                self._dns_transport = None

        self._dns_task = loop.create_task(_bind())

    async def _handle_dns_query(self, data: bytes, addr):
        if len(data) < 12 or len(data) > 4096:
            return
        sid = os.urandom(16)
        frame = Frame(sid, 0, FLAG_DNS, data)
        async with self.lock:
            self._dns_pending[sid] = (addr, time.monotonic())
        self._last_activity = time.monotonic()
        await self._enqueue_dns_frame(frame)

    async def _enqueue_dns_frame(self, frame: Frame):
        async with self.lock:
            self._dns_outbox.append(frame)

    def _prune_dns_pending(self):
        now = time.monotonic()
        expired = [sid for sid, (_, ts) in self._dns_pending.items() if now - ts > 30]
        for sid in expired:
            del self._dns_pending[sid]

    # ── URL selection ──

    def _expire_quarantines(self):
        """Снимает истёкшие карантины и даёт URL свежую попытку."""
        now = time.time()
        for url, until in list(self._url_cooldown_until.items()):
            if until <= now:
                self._url_cooldown_until.pop(url, None)
                self._url_failures.pop(url, None)

    def _available_urls(self):
        now = time.time()
        return [u for u in self.server_urls if self._url_cooldown_until.get(u, 0) <= now]

    def _mark_success(self, url):
        fails = self._url_failures.get(url, 0)
        was_quarantined = url in self._url_cooldown_until
        if fails > 0 or was_quarantined:
            self._url_failures.pop(url, None)
            self._url_cooldown_until.pop(url, None)
            logger.info("URL recovered: %s", url)
        self._url_failures[url] = 0

    def _mark_failure(self, url):
        now = time.time()
        fails = self._url_failures.get(url, 0) + 1
        self._url_failures[url] = fails
        # Перевзводим карантин после истечения предыдущего: старый код
        # проверял только наличие ключа, поэтому повторно не карантинил.
        if fails >= self.url_fail_limit and self._url_cooldown_until.get(url, 0) <= now:
            self._url_cooldown_until[url] = now + self.url_cooldown_seconds
            logger.warning("URL quarantined for %ds: %s", self.url_cooldown_seconds, url)

    def _pick_server_base(self):
        pool = self._available_urls()
        if not pool:
            return ""
        if len(pool) == 1 or self.server_selector == "random":
            return random.choice(pool)
        base = pool[self._rr_index % len(pool)]
        self._rr_index += 1
        return base

    def url_status(self) -> list[dict]:
        """Снимок состояния URL для UI: включён, карантин, счётчик ошибок."""
        now = time.time()
        status = []
        for url in self.all_server_urls:
            until = self._url_cooldown_until.get(url, 0)
            quarantined = until > now
            status.append({
                "url": url,
                "enabled": url not in self.disabled_urls,
                "quarantined": quarantined,
                "cooldown_remaining": max(0, int(round(until - now))) if quarantined else 0,
                "errors": int(self._url_failures.get(url, 0)),
            })
        return status

    def reset_url_status(self) -> None:
        """Сбрасывает счётчики ошибок и карантин всех URL."""
        self._url_failures.clear()
        self._url_cooldown_until.clear()
        self._all_q_logged = False
        logger.info("URL error counters and quarantines reset")

    def set_disabled_urls(self, disabled) -> None:
        """Обновляет список выключенных URL на лету (без перезапуска)."""
        self.disabled_urls = {str(u).rstrip("/") for u in (disabled or []) if u}
        self.server_urls = [u for u in self.all_server_urls if u not in self.disabled_urls]
        self._no_url_warned = False

    # ── Polling loop ──

    async def _subscription_refresh_loop(self):
        while not self._stop:
            await asyncio.sleep(self._sub_interval)
            if self._stop:
                break
            try:
                sub = load_subscription(self._sub_source)
                apply_subscription(self.cfg, sub)
                urls = self.cfg.get("client", {}).get("server_urls") or []
                all_urls = [u.rstrip("/") for u in urls if u]
                disabled = {u.rstrip("/") for u in (self.cfg.get("client", {}).get("disabled_urls") or [])}
                self.all_server_urls = all_urls
                self.server_urls = [u for u in all_urls if u not in disabled]
                self.server_base = (self.server_urls[0] if self.server_urls else
                                    (all_urls[0] if all_urls else self.server_base))
                self.split_router = SplitRouter(self.cfg)
                logger.info("subscription refreshed: %d nodes", len(self.server_urls))
            except Exception as exc:
                logger.warning("subscription refresh failed: %s", exc)

    async def poll_loop(self):
        if self._sub_source and self._sub_task is None:
            self._sub_task = asyncio.create_task(self._subscription_refresh_loop())
        while not self._stop:
            if not self.server_urls:
                if not self._no_url_warned:
                    logger.warning("no enabled server URLs; polling paused")
                    self._no_url_warned = True
                await asyncio.sleep(1.0)
                continue
            self._no_url_warned = False
            self._expire_quarantines()
            if not self._available_urls():
                now = time.time()
                until = min(self._url_cooldown_until.get(u, now) for u in self.server_urls)
                wait = max(0.5, min(until - now, 30.0))
                if not self._all_q_logged:
                    logger.warning("all server URLs are quarantined; waiting %.0fs", wait)
                    self._all_q_logged = True
                await asyncio.sleep(wait)
                continue
            self._all_q_logged = False
            if self.idle_timeout_enabled:
                idle_elapsed = time.monotonic() - self._last_activity
                if idle_elapsed >= self.idle_timeout_seconds:
                    if not self._idle_logged:
                        logger.info("idle timeout (%ds): pausing polls", self.idle_timeout_seconds)
                        self._idle_logged = True
                    async with self.lock:
                        for sid, sess in list(self.sessions.items()):
                            try:
                                sess.writer.close()
                            except Exception:
                                pass
                        self.sessions.clear()
                    await asyncio.sleep(0.5)
                    continue
                elif self._idle_logged:
                    logger.info("activity resumed, resuming polls")
                    self._idle_logged = False
            try:
                await self._poll_once()
            except Exception as e:
                logger.warning("poll error: %s", e)
            jitter = random.randint(-self.poll_jitter_ms, self.poll_jitter_ms)
            delay_ms = max(10, self.poll_interval_ms + jitter)
            await asyncio.sleep(delay_ms / 1000)

    async def _poll_once(self):
        groups: dict[tuple[str, tuple[str, ...]], list] = defaultdict(list)
        async with self.lock:
            dead_sids = []
            for sid, sess in self.sessions.items():
                base = sess.server_base or self.server_base
                key = (base, tuple(sess.route or ()))
                group = groups[key]
                if sess.pending_new is not None:
                    group.append(sess.pending_new)
                    sess.pending_new = None
                if sess.outgoing:
                    chunk = bytes(sess.outgoing[: self.max_chunk_bytes])
                    del sess.outgoing[: len(chunk)]
                    group.append(Frame(sid, sess.next_seq(), FLAG_DATA, chunk))
                if sess.closed and not sess.outgoing and not sess.fin_sent:
                    group.append(Frame(sid, sess.next_seq(), FLAG_FIN, b""))
                    sess.fin_sent = True
                    dead_sids.append(sid)
            for sid in dead_sids:
                del self.sessions[sid]

            if self._fin_outbox:
                for base, sid in self._fin_outbox:
                    groups[(base or self.server_base, ())].append(Frame(sid, 0, FLAG_FIN, b""))
                self._fin_outbox = []

            if self._dns_outbox:
                # DNS шлём через узел, где уже есть живые сессии: так запрос
                # не уйдёт на заведомо заблокированный URL.
                live_bases = sorted({sess.server_base or self.server_base
                                     for sess in self.sessions.values()})
                for frame in self._dns_outbox:
                    base = (random.choice(live_bases) if live_bases
                            else self._pick_server_base() or self.server_base)
                    groups[(base, ())].append(frame)
                self._dns_outbox = []
            self._prune_dns_pending()

            # Боевые poll-запросы — только на входные узлы живых сессий.
            # Остальные URL проверяем фоном: их таймауты не должны
            # задерживать ни трафик, ни первый запрос после простоя.
            available = set(self._available_urls())

        needed = {key[0] for key in groups}
        for base in available - needed:
            if base not in self._health_inflight:
                self._health_inflight.add(base)
                asyncio.create_task(self._health_probe(base))

        if not groups:
            return

        # Сессии на отключённых/карантинных URL работать не могут.
        for key in list(groups):
            base = key[0]
            if base not in available:
                await self._fail_base_sessions(base, "URL disabled or quarantined")
                for k in [k for k in groups if k[0] == base]:
                    groups.pop(k, None)

        if not groups:
            return

        results = await asyncio.gather(
            *(self._poll_base(base, frames, route) for (base, route), frames in groups.items()),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                logger.error("poll task error: %s", r)

    async def _health_probe(self, url_base: str) -> None:
        """Фоновая проверка неиспользуемого URL: карантин и выбор маршрута
        должны видеть реальную доступность, но не тормозить трафик."""
        try:
            await self._poll_base(url_base, [], timeout=3.0)
        except Exception as exc:
            logger.debug("health poll error (%s): %s", url_base, exc)
        finally:
            self._health_inflight.discard(url_base)

    async def _poll_base(self, url_base: str, frames_to_send,
                         route: tuple[str, ...] = (),
                         timeout: float | None = None) -> None:
        """Один poll-запрос к конкретному входному URL."""
        if self.pad_polls:
            frames_to_send = pad_frames(frames_to_send)
        batch = pack_frames(frames_to_send)
        blob = encrypt(self.enc_key, batch)

        offset = self._time_offsets.get(url_base, 0)
        now = time.time() + offset
        ts = str(int(now))
        route_hdr = ",".join(route) if len(route) > 1 else ""
        route_bytes = route_hdr.encode() if route_hdr else b""
        if self.user_id:
            mac = sign(self.hmac_key, self.client_id + self.user_id.encode()
                       + self.device_id.encode() + route_bytes + ts.encode() + blob)
        else:
            mac = sign(self.hmac_key, self.client_id + route_bytes + ts.encode() + blob)

        params = {"t": ts}
        headers = {"X-Cid": b64u_encode(self.client_id), "X-Mac": mac, "X-Proto": PROTO_VERSION}
        if self.user_id:
            # CDN (TurboFlare) блокирует запросы, где в заголовке есть UUID
            # в нижнем регистре (403, x-reason-code: 7). Верхний регистр
            # проходит; сервер приводит значение обратно к нижнему.
            headers["X-User"] = self.user_id.upper()
            headers["X-Device"] = self.device_id.upper()
        if route_hdr:
            headers["X-Route"] = route_hdr
        if self.host_header:
            headers["Host"] = self.host_header
        if self.poll_data_in == "header":
            headers["X-Data"] = b64u_encode(blob)

        kwargs = {"params": params, "headers": headers}
        if self.poll_data_in == "body":
            kwargs["content"] = b64u_encode(blob)
        if timeout is not None:
            kwargs["timeout"] = timeout

        self._poll_count += 1
        url = url_base + random_cdn_path(self.poll_path)
        try:
            async with self.http.stream(self.poll_method, url, **kwargs) as resp:
                if "Date" in resp.headers:
                    try:
                        import email.utils
                        server_time = email.utils.parsedate_to_datetime(resp.headers["Date"]).timestamp()
                        new_offset = int(server_time - time.time())
                        if abs(new_offset - offset) > 2:
                            logger.info("Time sync: %s drift %ds, adjusting", url_base, new_offset)
                            self._time_offsets[url_base] = new_offset
                    except Exception:
                        pass

                if resp.status_code == 403:
                    logger.warning("ERROR 403: Forbidden. Check PSK and Time Sync!")
                if resp.status_code >= 400:
                    # Считаем ошибку ровно один раз: раньше _mark_failure()
                    # вызывался ещё и в except после raise_for_status().
                    self._mark_failure(url_base)
                    logger.error("poll HTTP %s from %s", resp.status_code, url_base)
                    await self._handle_base_failure(url_base, f"HTTP {resp.status_code}", bool(frames_to_send))
                    return
                ctype = resp.headers.get("Content-Type", "").lower()
                if "octet-stream" not in ctype:
                    # Маскировочный ответ сервера (fake 200). Обычно значит
                    # неверный user/device, лимит устройств или маршрут.
                    self._mark_failure(url_base)
                    logger.warning("unexpected response from %s (%s); check user/device/route",
                                   url_base, ctype or "no content-type")
                    await self._handle_base_failure(url_base, "unexpected content-type",
                                                    bool(frames_to_send))
                    return
                self._mark_success(url_base)
                await self._handle_stream_response(resp)
        except Exception as e:
            self._mark_failure(url_base)
            if "403" not in str(e):
                logger.error("poll request failed (%s): %s", url_base, e)
            await self._handle_base_failure(url_base, str(e), bool(frames_to_send))

    async def _handle_base_failure(self, url_base: str, reason: str, had_frames: bool) -> None:
        """Закрывает сессии, закреплённые за упавшим URL, если в запросе
        были их данные или URL уже ушёл в карантин."""
        quarantined = self._url_cooldown_until.get(url_base, 0) > time.time()
        if had_frames or quarantined:
            await self._fail_base_sessions(url_base, reason)

    async def _fail_base_sessions(self, url_base: str, reason: str) -> None:
        closed = 0
        async with self.lock:
            for sid, sess in list(self.sessions.items()):
                if (sess.server_base or self.server_base) != url_base:
                    continue
                self.sessions.pop(sid, None)
                closed += 1
                try:
                    sess.writer.close()
                except Exception:
                    pass
        if closed:
            logger.warning("closed %d session(s) pinned to failed URL %s (%s)",
                           closed, url_base, reason)

    async def _handle_stream_response(self, resp):
        buf = bytearray()
        mode = "unknown"
        first_record = True
        dns_replies = []
        records = 0
        async for chunk in resp.aiter_bytes():
            if not chunk:
                continue
            buf.extend(chunk)
            if mode == "unknown" and len(buf) >= 2:
                if bytes(buf[:2]) == RESP_STREAM_MAGIC:
                    mode = "stream"
                    del buf[:2]
                else:
                    mode = "batch"
            if mode == "batch":
                continue
            while len(buf) >= 2:
                rec_len = struct.unpack_from("!H", buf, 0)[0]
                if rec_len == 0 or len(buf) < 2 + rec_len:
                    break
                record = bytes(buf[2:2 + rec_len])
                del buf[:2 + rec_len]
                try:
                    plain = decrypt(self.enc_key, record)
                    frame, _ = Frame.decode(plain, 0)
                except Exception as e:
                    if first_record:
                        logger.warning("stream record decrypt failed, falling back to batch: %s", e)
                        mode = "batch"
                        buf = bytearray(RESP_STREAM_MAGIC) + buf
                        break
                    logger.error("stream record error: %s", e)
                    continue
                first_record = False
                records += 1
                reply = await self._dispatch_single_frame(frame)
                if reply:
                    dns_replies.append(reply)
        if mode == "batch":
            body = bytes(buf)
            if body:
                try:
                    incoming_batch = decrypt(self.enc_key, body)
                    incoming_frames = unpack_frames(incoming_batch)
                except Exception as e:
                    logger.error("decrypt/unpack error: %r", e)
                else:
                    for f in incoming_frames:
                        reply = await self._dispatch_single_frame(f)
                        if reply:
                            dns_replies.append(reply)
        for addr, payload in dns_replies:
            try:
                self._dns_transport.sendto(payload, addr)
            except Exception as e:
                logger.error("dns reply failed: %s", e)

    async def _dispatch_single_frame(self, f):
        if f.flags & FLAG_DNS:
            async with self.lock:
                entry = self._dns_pending.pop(f.session_id, None)
            if entry:
                addr, _ts = entry
                return (addr, f.payload)
            return None

        async with self.lock:
            sess = self.sessions.get(f.session_id)
        if not sess:
            return None

        if (f.flags & FLAG_DATA) and f.payload:
            try:
                sess.writer.write(f.payload)
                await sess.writer.drain()
            except Exception as e:
                logger.error("session write error: %s", e)
                await self._drop_session(f.session_id)
                return None
            self._last_activity = time.monotonic()
        if f.flags & FLAG_FIN:
            try:
                sess.writer.close()
            except Exception:
                pass
        return None

    async def _drop_session(self, sid: bytes):
        async with self.lock:
            sess = self.sessions.pop(sid, None)
            if sess is not None:
                self._fin_outbox.append((sess.server_base, sid))
        if sess is not None:
            try:
                sess.writer.close()
            except Exception:
                pass

    async def stop(self):
        self._stop = True
        if self._sub_task:
            self._sub_task.cancel()
        if self._dns_task:
            self._dns_task.cancel()
        if self._dns_transport:
            self._dns_transport.close()
        await self.http.aclose()
