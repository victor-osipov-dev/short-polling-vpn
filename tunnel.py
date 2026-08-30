"""
Общий туннель для VPN-клиентов.

Содержит:
  - ClientSession — состояние одной локальной TCP-сессии
  - ClientTunnel — базовый класс туннеля (сессии, пуллинг, DNS relay, URL selection)

Используется desktop_client.py, client.py и android proxy_engine.py.
"""

import asyncio
import logging
import os
import random
import struct
import time
from typing import Optional

import httpx

from protocol import (
    Frame, FLAG_NEW, FLAG_DATA, FLAG_FIN, FLAG_DNS,
    PROTO_VERSION, RESP_STREAM_MAGIC,
    pack_frames, unpack_frames, new_session_id,
)
from crypto_utils import (
    derive_key, derive_hmac_key, encrypt, decrypt, sign,
    b64u_encode, b64u_decode,
)
from cdn_paths import random_cdn_path

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
        client_cfg = cfg["client"]
        sec_cfg = cfg["security"]

        self.client_id = os.urandom(16)
        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        self.server_urls = [u.rstrip("/") for u in urls if u]
        self.server_base = self.server_urls[0] if self.server_urls else client_cfg.get("server_url", "").rstrip("/")
        self.server_selector = str(client_cfg.get("server_selector", "random")).lower()
        self._rr_index = 0
        self._url_failures = {}
        self._url_cooldown_until = {}
        self.url_fail_limit = max(1, int(client_cfg.get("url_fail_limit", 3)))
        self.url_cooldown_seconds = max(1, int(client_cfg.get("url_cooldown_seconds", 60)))
        self.poll_path = client_cfg.get("poll_path", "/poll")
        self.poll_interval_ms = int(client_cfg.get("poll_interval_ms", 200))
        self.poll_jitter_ms = int(client_cfg.get("poll_jitter_ms", 50))
        self.max_chunk_bytes = int(client_cfg.get("max_chunk_bytes", 4096))
        self.poll_method = client_cfg.get("poll_method", "POST").upper()
        self.poll_data_in = client_cfg.get("poll_data_in", "body")
        self.host_header = client_cfg.get("host_header") or None
        verify_tls = client_cfg.get("verify_tls", True)
        trust_env = client_cfg.get("trust_env_proxy", False)

        self.enc_key = derive_key(sec_cfg["psk"].strip())
        self.hmac_key = derive_hmac_key(sec_cfg["psk"].strip())

        idle_cfg = client_cfg.get("idle_timeout", {})
        self.idle_timeout_enabled = idle_cfg.get("enabled", False)
        self.idle_timeout_seconds = int(idle_cfg.get("seconds", 300))
        self._last_activity = time.monotonic()
        self._idle_logged = False

        self.sessions: dict = {}
        self.lock = asyncio.Lock()
        self.http = httpx.AsyncClient(http2=True, verify=verify_tls, timeout=15.0, trust_env=trust_env)
        self._stop = False

        self.time_offset = 0

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

        logger.info("client_id=%s", self.client_id.hex())

    # ── Сессии ──

    async def register_session(self, writer: asyncio.StreamWriter, host: str, port: int) -> bytes:
        sid = new_session_id()
        sess = ClientSession(sid, writer)
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

    def _available_urls(self):
        now = time.time()
        avail = [u for u in self.server_urls if self._url_cooldown_until.get(u, 0) <= now]
        if not avail and self.server_urls:
            logger.warning("all server URLs quarantined; resetting cooldowns")
            self._url_cooldown_until.clear()
            self._url_failures.clear()
            return self.server_urls
        return avail

    def _mark_success(self, url):
        if url in self._url_failures or url in self._url_cooldown_until:
            self._url_failures.pop(url, None)
            self._url_cooldown_until.pop(url, None)
            logger.info("URL recovered: %s", url)
        self._url_failures[url] = 0

    def _mark_failure(self, url):
        fails = self._url_failures.get(url, 0) + 1
        self._url_failures[url] = fails
        if fails >= self.url_fail_limit and url not in self._url_cooldown_until:
            self._url_cooldown_until[url] = time.time() + self.url_cooldown_seconds
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

    # ── Polling loop ──

    async def poll_loop(self):
        while not self._stop:
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
        frames_to_send = []
        async with self.lock:
            dead_sids = []
            for sid, sess in self.sessions.items():
                if sess.pending_new is not None:
                    frames_to_send.append(sess.pending_new)
                    sess.pending_new = None
                if sess.outgoing:
                    chunk = bytes(sess.outgoing[: self.max_chunk_bytes])
                    del sess.outgoing[: len(chunk)]
                    frames_to_send.append(Frame(sid, sess.next_seq(), FLAG_DATA, chunk))
                if sess.closed and not sess.outgoing and not sess.fin_sent:
                    frames_to_send.append(Frame(sid, sess.next_seq(), FLAG_FIN, b""))
                    sess.fin_sent = True
                    dead_sids.append(sid)
            for sid in dead_sids:
                del self.sessions[sid]
            if self._fin_outbox:
                for sid in self._fin_outbox:
                    frames_to_send.append(Frame(sid, 0, FLAG_FIN, b""))
                self._fin_outbox = []
            if self._dns_outbox:
                frames_to_send.extend(self._dns_outbox)
                self._dns_outbox = []
            self._prune_dns_pending()

        batch = pack_frames(frames_to_send)
        blob = encrypt(self.enc_key, batch)

        now = time.time() + self.time_offset
        ts = str(int(now))
        mac = sign(self.hmac_key, self.client_id + ts.encode() + blob)

        params = {"t": ts}
        headers = {"X-Cid": b64u_encode(self.client_id), "X-Mac": mac, "X-Proto": PROTO_VERSION}
        if self.host_header:
            headers["Host"] = self.host_header
        if self.poll_data_in == "header":
            headers["X-Data"] = b64u_encode(blob)

        kwargs = {"params": params, "headers": headers}
        if self.poll_data_in == "body":
            kwargs["content"] = b64u_encode(blob)

        self._poll_count += 1
        try:
            url_base = self._pick_server_base()
            url = url_base + random_cdn_path(self.poll_path)
            async with self.http.stream(self.poll_method, url, **kwargs) as resp:
                if "Date" in resp.headers:
                    try:
                        import email.utils
                        server_time = email.utils.parsedate_to_datetime(resp.headers["Date"]).timestamp()
                        new_offset = int(server_time - (now - self.time_offset))
                        if abs(new_offset - self.time_offset) > 2:
                            logger.info("Time sync: server drift %ds, adjusting", new_offset)
                            self.time_offset = new_offset
                    except Exception:
                        pass

                if resp.status_code == 403:
                    logger.warning("ERROR 403: Forbidden. Check PSK and Time Sync!")
                if resp.status_code >= 400:
                    self._mark_failure(url_base)
                else:
                    self._mark_success(url_base)
                resp.raise_for_status()
                await self._handle_stream_response(resp)
        except Exception as e:
            self._mark_failure(url_base if 'url_base' in locals() else self.server_base)
            if "403" not in str(e):
                logger.error("poll request failed: %s", e)

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
                    logger.error("decrypt/unpack error: %s", e)
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
            self._fin_outbox.append(sid)
        if sess is not None:
            try:
                sess.writer.close()
            except Exception:
                pass

    async def stop(self):
        self._stop = True
        if self._dns_task:
            self._dns_task.cancel()
        if self._dns_transport:
            self._dns_transport.close()
        await self.http.aclose()
