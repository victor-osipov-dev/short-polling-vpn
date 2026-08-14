"""
VPN-клиент.

1. Поднимает локальный SOCKS5-сервер (без аутентификации, поддерживается
   только команда CONNECT — этого достаточно для проксирования TCP-трафика
   браузеров/приложений).
2. Каждое принятое SOCKS5-соединение становится "сессией" внутри туннеля.
3. Фоновый цикл раз в poll_interval_ms (+jitter) отправляет один короткий
   HTTP GET-запрос: в query-параметрах едут накопленные исходящие данные
   (зашифрованные, с явной длиной), в ответе сервер присылает то, что
   накопилось входящего. Никаких долгоживущих соединений — каждый запрос
   завершается сразу же, у ответа всегда известный Content-Length.
"""

import asyncio
import logging
import os
import random
import socket
import struct
import time

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

logger = logging.getLogger("vpn-client")


class ClientSession:
    """Состояние одной локальной TCP-сессии (принятой по SOCKS5)."""

    def __init__(self, session_id: bytes, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.writer = writer
        self.seq = 0
        self.outgoing = bytearray()   # данные, ещё не отправленные на сервер
        self.pending_new = None        # закодированный NEW-кадр, ждущий отправки
        self.closed = False            # локальная сторона закрылась (нужно послать FIN)
        self.fin_sent = False

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


class ClientTunnel:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        client_cfg = cfg["client"]
        sec_cfg = cfg["security"]

        self.client_id = os.urandom(16)
        urls = client_cfg.get("server_urls") or [client_cfg.get("server_url", "")]
        self.server_urls = [u.rstrip("/") for u in urls if u]
        self.server_base = self.server_urls[0] if self.server_urls else client_cfg.get("server_url", "").rstrip("/")
        self.server_selector = str(client_cfg.get("server_selector", "round")).lower()
        self._rr_index = 0
        self.poll_path = client_cfg.get("poll_path", "/poll")
        self.server_url = self.server_base + self.poll_path
        self.poll_interval_ms = int(client_cfg.get("poll_interval_ms", 200))
        self.poll_jitter_ms = int(client_cfg.get("poll_jitter_ms", 50))
        self.max_chunk_bytes = int(client_cfg.get("max_chunk_bytes", 4096))
        self.poll_method = client_cfg.get("poll_method", "POST").upper()
        self.poll_data_in = client_cfg.get("poll_data_in", "body")
        self.host_header = client_cfg.get("host_header") or None
        verify_tls = client_cfg.get("verify_tls", True)

        self.enc_key = derive_key(sec_cfg["psk"])
        self.hmac_key = derive_hmac_key(sec_cfg["psk"])

        idle_cfg = client_cfg.get("idle_timeout", {})
        self.idle_timeout_enabled = idle_cfg.get("enabled", False)
        self.idle_timeout_seconds = int(idle_cfg.get("seconds", 300))
        self._last_activity = time.monotonic()
        self._idle_logged = False

        self.sessions: dict = {}
        self.lock = asyncio.Lock()
        self.http = httpx.AsyncClient(http2=True, verify=verify_tls, timeout=15.0)
        self._stop = False

        dns_cfg = client_cfg.get("dns_relay", {})
        self.dns_relay_enabled = dns_cfg.get("enabled", False)
        self.dns_bind_host = dns_cfg.get("bind_host", "127.0.0.1")
        self.dns_bind_port = int(dns_cfg.get("bind_port", 5353))
        self._dns_pending: dict = {}  # sid -> (addr, ts)
        self._dns_outbox: list = []   # FLAG_DNS frames awaiting next poll
        self._fin_outbox: list = []   # sid'ы мёртвых сессий, для которых нужно отправить FIN серверу
        self._dns_transport = None
        self._dns_protocol = None
        self._dns_task = None

        logger.info("client_id=%s", self.client_id.hex())

    # ---------- регистрация / обратная связь от SOCKS5-обработчика ----------

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

    # --------------------------- DNS relay ---------------------------

    def _start_dns_relay(self):
        """Запускает локальный UDP-сервер DNS-резолвера (только если включён)."""
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
                logger.info("DNS relay listening on %s:%d",
                            self.dns_bind_host, self.dns_bind_port)
            except Exception as e:
                logger.error("failed to start DNS relay on %s:%d: %s",
                             self.dns_bind_host, self.dns_bind_port, e)
                self._dns_transport = None

        self._dns_task = loop.create_task(_bind())

    async def _handle_dns_query(self, data: bytes, addr):
        if len(data) < 12 or len(data) > 4096:
            return
        sid = os.urandom(16)
        frame = Frame(sid, 0, FLAG_DNS, data)
        async with self.lock:
            self._dns_pending[sid] = (addr, time.monotonic())
        logger.debug(f"[dns] queued {len(data)}B query from {addr}")
        self._last_activity = time.monotonic()
        await self._enqueue_dns_frame(frame)

    async def _enqueue_dns_frame(self, frame: Frame):
        async with self.lock:
            self._dns_outbox.append(frame)

    def _prune_dns_pending(self):
        now = time.monotonic()
        expired = [sid for sid, (_, ts) in self._dns_pending.items()
                   if now - ts > 30]
        for sid in expired:
            del self._dns_pending[sid]

    # ---------------------------- поллинг ----------------------------

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

    def _pick_server_base(self):
        """Выбирает базу URL на каждый poll: round-robin или random."""
        if not self.server_urls:
            return ""
        if len(self.server_urls) == 1 or self.server_selector == "random":
            return random.choice(self.server_urls)
        base = self.server_urls[self._rr_index % len(self.server_urls)]
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
                    logger.debug(f"[client] pending NEW for session {sid.hex()[:8]}")
                if sess.outgoing:
                    chunk = bytes(sess.outgoing[: self.max_chunk_bytes])
                    del sess.outgoing[: len(chunk)]
                    frames_to_send.append(Frame(sid, sess.next_seq(), FLAG_DATA, chunk))
                    logger.debug(f"[client] sending {len(chunk)} bytes for session {sid.hex()[:8]}")
                if sess.closed and not sess.outgoing and not sess.fin_sent:
                    frames_to_send.append(Frame(sid, sess.next_seq(), FLAG_FIN, b""))
                    sess.fin_sent = True
                    dead_sids.append(sid)
                    logger.debug(f"[client] sending FIN for session {sid.hex()[:8]}")
            for sid in dead_sids:
                del self.sessions[sid]
            if self._fin_outbox:
                for sid in self._fin_outbox:
                    frames_to_send.append(Frame(sid, 0, FLAG_FIN, b""))
                    logger.debug(f"[client] sending orphan FIN for session {sid.hex()[:8]}")
                self._fin_outbox = []
            if self._dns_outbox:
                frames_to_send.extend(self._dns_outbox)
                self._dns_outbox = []
            self._prune_dns_pending()

        batch = pack_frames(frames_to_send)
        blob = encrypt(self.enc_key, batch)
        ts = str(int(time.time()))
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

        logger.debug(f"[client] poll: {self.poll_method} data_in={self.poll_data_in} "
                     f"{len(frames_to_send)} frames, {len(blob)}B blob")
        try:
            async with self.http.stream(self.poll_method, self._pick_server_base() + self.poll_path, **kwargs) as resp:
                resp.raise_for_status()
                await self._handle_stream_response(resp)
        except Exception as e:
            logger.error(f"[client] poll request failed: {e}")
            return

    async def _handle_stream_response(self, resp):
        """Потоково читает ответ: magic + записи [2B len][AESGCM(кадр)].
        Каждый рекорд расшифровывается и раздаётся в SOCKS5 по мере прихода,
        не дожидаясь всего тела ответа. Если magic не найден — старый формат
        (один зашифрованный батч), обрабатываем целиком по завершении стрима."""
        buf = bytearray()
        mode = "unknown"  # unknown | stream | batch
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
                        # Не исключено, что случайный nonce старого формата совпал
                        # с magic — откатываемся к побайтовому (batch) режиму.
                        logger.warning(f"[client] stream record decrypt failed, "
                                       f"falling back to batch: {e}")
                        mode = "batch"
                        buf = bytearray(RESP_STREAM_MAGIC) + buf
                        break
                    logger.error(f"[client] stream record error: {e}")
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
                    logger.error(f"[client] poll: decrypt/unpack error: {e}")
                else:
                    for f in incoming_frames:
                        reply = await self._dispatch_single_frame(f)
                        if reply:
                            dns_replies.append(reply)
        else:
            logger.debug(f"[client] poll: got {records} stream records")
        for addr, payload in dns_replies:
            try:
                self._dns_transport.sendto(payload, addr)
                logger.debug(f"[dns] reply {len(payload)}B to {addr}")
            except Exception as e:
                logger.error(f"[dns] failed to send reply to {addr}: {e}")

    async def _dispatch_single_frame(self, f):
        """Обрабатывает один входящий кадр. Возвращает (addr, payload) для
        DNS-ответа либо None. Запись в SOCKS5 выполняется ВНЕ lock, чтобы
        медленный/мёртвый сокет приложения не блокировал поллинг."""
        if f.flags & FLAG_DNS:
            async with self.lock:
                entry = self._dns_pending.pop(f.session_id, None)
            if entry:
                addr, _ts = entry
                return (addr, f.payload)
            logger.warning(f"[dns] no pending query for sid {f.session_id.hex()[:8]}")
            return None

        async with self.lock:
            sess = self.sessions.get(f.session_id)
        sid = f.session_id.hex()[:8]
        if not sess:
            logger.debug(f"[client] session {sid} not found")
            return None

        if (f.flags & FLAG_DATA) and f.payload:
            try:
                logger.debug(f"[client] session {sid} writing {len(f.payload)} bytes to SOCKS5")
                sess.writer.write(f.payload)
                await sess.writer.drain()
            except Exception as e:
                logger.error(f"[client] session {sid} write error, dropping session: {e}")
                await self._drop_session(f.session_id)
                return None
            self._last_activity = time.monotonic()
        if f.flags & FLAG_FIN:
            logger.info(f"[client] session {sid} FIN received")
            try:
                sess.writer.close()
            except Exception:
                pass
        return None

    async def _drop_session(self, sid: bytes):
        """Выкидывает сессию из self.sessions и ставит её sid в очередь на
        отправку FIN серверу, чтобы тот остановил поток данных по ней."""
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


# --------------------------- SOCKS5-сервер ---------------------------

SOCKS_VERSION = 0x05


def enable_tcp_keepalive(transport) -> None:
    """Включает TCP keepalive на сокете, чтобы idle-соединения не резались
    таймаутами, а реально мёртвые — закрывались ОС."""
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
    """Минимальный SOCKS5: без аутентификации, только CONNECT."""
    header = await reader.readexactly(2)
    ver, nmethods = header
    if ver != SOCKS_VERSION:
        raise ConnectionError("unsupported SOCKS version")
    await reader.readexactly(nmethods)  # список методов авторизации клиента, игнорируем
    writer.write(bytes([SOCKS_VERSION, 0x00]))  # выбираем метод 0x00 - без авторизации
    await writer.drain()

    req_header = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = req_header
    if cmd != 0x01:  # только CONNECT
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        raise ConnectionError("only CONNECT is supported")

    if atyp == 0x01:  # IPv4
        addr_bytes = await reader.readexactly(4)
        host = socket.inet_ntoa(addr_bytes)
    elif atyp == 0x03:  # domain name
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("utf-8")
    elif atyp == 0x04:  # IPv6
        addr_bytes = await reader.readexactly(16)
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
    else:
        raise ConnectionError("unsupported address type")

    port = struct.unpack("!H", await reader.readexactly(2))[0]

    # Отвечаем "успех" сразу (реальное соединение до целевого хоста установит сервер туннеля)
    writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()

    return host, port


async def handle_socks_client(tunnel: ClientTunnel, reader: asyncio.StreamReader,
                               writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    logger.info(f"socks5: new connection from {peer}")
    try:
        host, port = await _socks5_handshake(reader, writer)
    except Exception as e:
        logger.error("socks handshake failed from %s: %s", peer, e)
        writer.close()
        return

    sid = await tunnel.register_session(writer, host, port)
    logger.info(f"socks5: registered session {sid.hex()[:8]} -> {host}:{port}")
    enable_tcp_keepalive(writer.transport)

    async def read_from_socks5():
        """Фоновый цикл: читает из SOCKS5 клиента, пишет в туннель"""
        try:
            while True:
                data = await reader.read(4096)
                if not data:
                    logger.info(f"socks5: {sid.hex()[:8]} got EOF from client")
                    break
                logger.debug(f"socks5: {sid.hex()[:8]} read {len(data)} bytes from client")
                await tunnel.feed_outgoing(sid, data)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"socks5: {sid.hex()[:8]} read error: {e}")
        finally:
            await tunnel.mark_closed(sid)
            logger.info(f"socks5: {sid.hex()[:8]} closed")
    
    # Запускаем фоновую задачу чтения, не блокируя обработчик
    asyncio.create_task(read_from_socks5())


async def run_socks5_server(tunnel: ClientTunnel, bind_host: str, bind_port: int):
    server = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w), bind_host, bind_port
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("SOCKS5 listening on %s", addrs)
    async with server:
        await server.serve_forever()


async def run_client(cfg: dict):
    tunnel = ClientTunnel(cfg)
    socks_cfg = cfg["client"]["socks5"]
    tunnel._start_dns_relay()
    poll_task = asyncio.create_task(tunnel.poll_loop())
    try:
        await run_socks5_server(tunnel, socks_cfg["bind_host"], socks_cfg["bind_port"])
    finally:
        poll_task.cancel()
        await tunnel.stop()