"""
Desktop VPN Client — исправленный аналог Android приложения.

Отличия от client.py:
  1. Случайные CDN-образные пути (как в Android proxy_engine.py)
     — обход кеша CDN, без которого stale timestamp и 403.
  2. Синхронизация времени по Date-заголовку сервера
     — решает проблему drift часов > hmac_window_seconds.
  3. .strip() PSK — защита от пробелов/переносов в конфиге.
  4. trust_env_proxy из конфига.

Запуск:
    python desktop_client.py --config config.yaml

Подключение:
    Настройте v2rayN (или браузер) на SOCKS5-прокси 127.0.0.1:8888
"""

import argparse
import asyncio
import logging
import os
import random
import socket
import struct
import sys
import time
import base64

import httpx
import yaml

from protocol import (
    Frame, FLAG_NEW, FLAG_DATA, FLAG_FIN, FLAG_DNS,
    PROTO_VERSION, RESP_STREAM_MAGIC,
    pack_frames, unpack_frames, new_session_id,
)
from crypto_utils import (
    derive_key, derive_hmac_key, encrypt, decrypt, sign,
    b64u_encode, b64u_decode,
)

logger = logging.getLogger("vpn-client")


class ClientSession:
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

        # .strip() PSK — как в Android, защита от пробелов в конфиге
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

        # Временная синхронизация (как в Android)
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

    # ── Случайные CDN-пути (из Android proxy_engine.py) ──

    def _random_path(self):
        """Генерирует случайное 'CDN-образное' продолжение пути поверх poll_path."""
        r = random
        dig = lambda n: ''.join(r.choice('0123456789abcdef') for _ in range(n))
        nid = lambda: str(r.randint(100, 99999999))
        base = self.poll_path.rstrip("/")

        pick = r.random()
        if pick < 0.18:
            ext = r.choice(['js', 'css'])
            nm = r.choice(['app', 'main', 'vendor', 'runtime', 'index', 'chunk'])
            p = f"/assets/{nm}.{dig(6)}.{ext}"
        elif pick < 0.30:
            p = f"/assets/{r.choice(['app', 'main', 'index', 'styles', 'vendor', 'bundle'])}.{r.choice(['js', 'css'])}"
        elif pick < 0.42:
            p = r.choice([
                f"/images/{nid()}.{r.choice(['jpg', 'webp', 'avif', 'png'])}",
                f"/img/{r.choice(['logo', 'banner', 'hero'])}.{r.choice(['png', 'webp'])}",
                f"/cdn/images/{nid()}.jpg",
                f"/media/{nid()}/thumbnail.jpg",
            ])
        elif pick < 0.52:
            p = r.choice([
                "/config.json", "/manifest.json", "/api/config",
                f"/locales/{r.choice(['en', 'de', 'fr', 'ru', 'es', 'it'])}.json",
                "/assets/config.json", "/assets/i18n/en-US.json",
            ])
        elif pick < 0.62:
            p = r.choice([
                f"/hls/{nid()}/master.m3u8",
                f"/hls/{nid()}/720p/index.m3u8",
                f"/video/{nid()}/seg-{r.randint(1, 99):03d}.ts",
                f"/videos/{nid()}.{r.choice(['mp4', 'mkv'])}",
            ])
        elif pick < 0.72:
            p = r.choice([
                "/_next/static/chunks/main.js",
                "/_next/static/chunks/webpack.js",
                "/_next/static/css/app.css",
                f"/assets/chunk-{r.choice(['settings', 'dashboard', 'editor', 'chat', 'login', 'profile'])}.js",
                "/_nuxt/app.js",
            ])
        elif pick < 0.80:
            p = r.choice([
                f"/download/{nid()}.zip",
                f"/objects/{nid()}/data",
                f"/uploads/{r.randint(2020, 2026)}/{r.randint(1, 12):02d}/{dig(8)}.{r.choice(['jpg', 'png'])}",
                f"/packages/{r.choice(['app', 'utils', 'core', 'tools'])}.tar.gz",
                f"/releases/v{r.randint(1, 9)}.{r.randint(0, 9)}.{r.randint(0, 9)}/app.zip",
            ])
        elif pick < 0.90:
            fam = r.choice(['inter', 'roboto', 'montserrat', 'lato', 'source-sans'])
            style = r.choice(['', 'bold-', 'regular-', 'medium-', 'semi-bold-'])
            p = f"/assets/fonts/{fam}-{style}{r.choice(['v1', 'v2', 'v3'])}.{r.choice(['woff2', 'woff', 'ttf'])}"
        else:
            p = r.choice([
                f"/api/users", f"/api/v{r.randint(1, 3)}/status",
                f"/content/{nid()}", f"/articles/{nid()}",
                f"/edge/config", f"/cdn/health",
            ])

        if r.random() < 0.35:
            p += r.choice([
                "?v=" + str(r.randint(1, 4)),
                "?v=" + str(r.randint(20260800, 20260899)),
                "?_=" + str(r.randint(1700000000, 1800000000)),
                "?cache=" + dig(6),
                "?version=" + str(r.randint(100, 999)),
            ])
        return base + p

    # ── SOCKS5 ──

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

        # Используем скорректированное время (как в Android)
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
            # Случайный CDN-путь вместо фиксированного /poll — КЛЮЧЕВОЕ ОТЛИЧИЕ
            url = url_base + self._random_path()
            async with self.http.stream(self.poll_method, url, **kwargs) as resp:
                # Синхронизация времени по Date-заголовку сервера (как в Android)
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


# ── SOCKS5-сервер ──

SOCKS_VERSION = 0x05


def enable_tcp_keepalive(transport) -> None:
    sock = transport.get_extra_info("socket")
    if sock is None:
        return
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        if hasattr(socket, "TCP_KEEPIDLE"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        if hasattr(socket, "TCP_KEEPINTVL"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
        if hasattr(socket, "TCP_KEEPCNT"):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
    except OSError:
        pass


async def _socks5_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    header = await reader.readexactly(2)
    ver, nmethods = header
    if ver != SOCKS_VERSION:
        raise ConnectionError("unsupported SOCKS version")
    await reader.readexactly(nmethods)
    writer.write(bytes([SOCKS_VERSION, 0x00]))
    await writer.drain()

    req_header = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = req_header
    if cmd == 0x03:
        return "UDP_ASSOCIATE", None, None

    if cmd != 0x01:
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        raise ConnectionError("only CONNECT is supported")

    if atyp == 0x01:
        addr_bytes = await reader.readexactly(4)
        host = socket.inet_ntoa(addr_bytes)
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("utf-8")
    elif atyp == 0x04:
        addr_bytes = await reader.readexactly(16)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise ConnectionError("unsupported address type")

    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return "CONNECT", host, port


async def handle_socks_client(tunnel: ClientTunnel, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        cmd, host, port = await _socks5_handshake(reader, writer)
    except Exception as e:
        logger.error("socks handshake failed from %s: %s", peer, e)
        writer.close()
        return

    if cmd == "UDP_ASSOCIATE":
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        writer.close()
        return

    writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()

    sid = await tunnel.register_session(writer, host, port)
    enable_tcp_keepalive(writer.transport)

    async def read_from_socks5():
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                await tunnel.feed_outgoing(sid, data)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            await tunnel.mark_closed(sid)

    asyncio.create_task(read_from_socks5())


async def run_socks5_server(tunnel: ClientTunnel, bind_host: str, bind_port: int):
    server = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w), bind_host, bind_port,
        reuse_address=True
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("SOCKS5 listening on %s", addrs)
    async with server:
        await server.serve_forever()


# ── HTTP CONNECT прокси-сервер ──

async def _http_connect_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    """Парсит HTTP CONNECT запрос и возвращает (host, port)."""
    buf = b""
    while True:
        chunk = await reader.read(4096)
        if not chunk:
            raise ConnectionError("connection closed during HTTP handshake")
        buf += chunk
        if b"\r\n\r\n" in buf:
            break
    first_line_end = buf.index(b"\r\n")
    first_line = buf[:first_line_end].decode("utf-8", errors="replace")
    parts = first_line.split()
    if len(parts) < 3 or parts[0].upper() != "CONNECT":
        raise ConnectionError(f"not a CONNECT request: {first_line[:100]}")

    host_port = parts[1]
    if ":" in host_port:
        host, port_str = host_port.rsplit(":", 1)
        port = int(port_str)
    else:
        host = host_port
        port = 443
    return host, port


async def handle_http_client(tunnel: ClientTunnel, reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    try:
        host, port = await _http_connect_handshake(reader, writer)
    except Exception as e:
        logger.error("http connect handshake failed from %s: %s", peer, e)
        try:
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        writer.close()
        return

    try:
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
    except Exception as e:
        logger.error("http connect response failed: %s", e)
        writer.close()
        return

    sid = await tunnel.register_session(writer, host, port)
    enable_tcp_keepalive(writer.transport)

    async def read_from_http():
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    break
                await tunnel.feed_outgoing(sid, data)
        except asyncio.CancelledError:
            raise
        except Exception:
            pass
        finally:
            await tunnel.mark_closed(sid)

    asyncio.create_task(read_from_http())


async def run_http_proxy_server(tunnel: ClientTunnel, bind_host: str, bind_port: int):
    server = await asyncio.start_server(
        lambda r, w: handle_http_client(tunnel, r, w), bind_host, bind_port,
        reuse_address=True
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("HTTP CONNECT proxy listening on %s", addrs)
    async with server:
        await server.serve_forever()


# ── Системный прокси (Windows) ──

_PROXY_OVERRIDES = (
    "localhost;127.*;10.*;192.168.*;"
    "172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;"
    "172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;"
    "172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*"
)


def _notify_proxy_change():
    """Вызывает InternetSetOption, чтобы Chrome/Edge/другие приложения
    подхватили новые настройки прокси без перезапуска."""
    try:
        import ctypes
        INTERNET_OPTION_SETTINGS_CHANGED = 39
        INTERNET_OPTION_REFRESH = 37
        ctypes.windll.wininet.InternetSetOptionW(
            0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(
            0, INTERNET_OPTION_REFRESH, 0, 0)
    except Exception:
        pass


def set_system_proxy_windows(host: str, socks_port: int, http_port: int, enable: bool = True):
    """Устанавливает/снимает системовый прокси на Windows.

    Формат ProxyServer: 'host:http_port' — стандартный HTTP прокси.
    Работает для всех приложений (WinHTTP, .NET, UWP, браузеры).
    """
    try:
        import winreg

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                try:
                    winreg.DeleteValue(key, "AutoConfigURL")
                except FileNotFoundError:
                    pass
                try:
                    winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
                    winreg.DeleteValue(key, "AutoConfigURL")
                except Exception:
                    pass
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ,
                    f"{host}:{http_port}")
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, _PROXY_OVERRIDES)
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)

        _notify_proxy_change()
        logger.info("System proxy %s: %s:%d",
            "set" if enable else "cleared", host, http_port)
    except Exception as e:
        logger.warning("Failed to set system proxy: %s", e)


# ── Точка входа ──

async def run_client(cfg: dict):
    tunnel = ClientTunnel(cfg)
    socks_cfg = cfg["client"]["socks5"]
    bind_host = socks_cfg.get("bind_host", "0.0.0.0")
    bind_port = socks_cfg.get("bind_port", 8888)
    http_port = socks_cfg.get("http_port", 8889)

    tunnel._start_dns_relay()

    # Устанавливаем системный прокси (только на Windows)
    if sys.platform == "win32" and bind_host in ("0.0.0.0", "127.0.0.1", "localhost"):
        set_system_proxy_windows("127.0.0.1", bind_port, http_port, True)

    poll_task = asyncio.create_task(tunnel.poll_loop())
    socks_task = asyncio.create_task(run_socks5_server(tunnel, bind_host, bind_port))
    http_task = asyncio.create_task(run_http_proxy_server(tunnel, bind_host, http_port))
    try:
        await asyncio.gather(socks_task, http_task)
    finally:
        poll_task.cancel()
        socks_task.cancel()
        http_task.cancel()
        await tunnel.stop()
        if sys.platform == "win32":
            set_system_proxy_windows("127.0.0.1", bind_port, http_port, False)


def main():
    parser = argparse.ArgumentParser(description="Desktop VPN Client (short-polling)")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    args = parser.parse_args()

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f)

    level_name = cfg.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    logger.info("Starting desktop client...")
    logger.info("Server URLs: %s", cfg["client"].get("server_urls", []))
    logger.info("Poll interval: %dms", cfg["client"].get("poll_interval_ms", 200))

    try:
        asyncio.run(run_client(cfg))
    except KeyboardInterrupt:
        logger.info("Stopped by user")


if __name__ == "__main__":
    main()
