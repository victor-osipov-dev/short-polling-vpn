"""
VPN-сервер.

Принимает короткие GET-запросы на /poll. На каждый запрос:
1. Проверяет HMAC и временное окно (anti-replay).
2. Расшифровывает батч кадров, применяет их (открывает новые TCP-соединения
   по FLAG_NEW, пишет данные по FLAG_DATA, закрывает по FLAG_FIN).
3. Отдаёт клиенту всё, что успело накопиться от целевых хостов, одним
   зашифрованным блоком в теле ответа — с заранее известным Content-Length,
   без chunked-передачи и без удержания соединения открытым.

Данные, приходящие от целевого хоста (интернета) в промежутках между
опросами клиента, буферизуются в ServerSession.incoming фоновой задачей
_pump_remote_to_buffer — так short polling не теряет данные между запросами.
"""

import asyncio
import logging
import socket
import struct
import time

from aiohttp import web

from protocol import (
    Frame, FLAG_NEW, FLAG_DATA, FLAG_FIN, FLAG_DNS,
    PROTO_VERSION, RESP_STREAM_MAGIC,
    pack_frames, unpack_frames,
)
from crypto_utils import (
    derive_key, derive_hmac_key, encrypt, decrypt, verify,
    b64u_encode, b64u_decode,
)

logger = logging.getLogger("vpn-server")

# Максимальный payload одного рекорда в потоковом ответе (X-Proto: 2).
# Рекорд = [2B длина][AESGCM(кадр)]; длина записи должна влезать в 2 байта,
# т.е. 60000 + overhead(28) <= 65535. Мелкие рекорды позволяют клиенту
# писать данные в SOCKS5 по мере поступления, а не после полной загрузки
# огромного тела ответа (лечит WinError 64 на больших ответах).
STREAM_RECORD_SIZE = 60000
AES_GCM_OVERHEAD = 12 + 16  # nonce + tag


def iter_stream_records(frames):
    """Генерирует зашифрованно-сырые plaintext каждого рекорда потокового
    ответа (без шифрования). Крупные DATA-кадры режутся на рекорды по
    STREAM_RECORD_SIZE."""
    for f in frames:
        if (f.flags & FLAG_DATA) and len(f.payload) > STREAM_RECORD_SIZE:
            for i in range(0, len(f.payload), STREAM_RECORD_SIZE):
                chunk = f.payload[i:i + STREAM_RECORD_SIZE]
                yield Frame(f.session_id, f.seq, FLAG_DATA, chunk).encode()
        else:
            yield f.encode()


def build_stream_response(enc_key, frames) -> bytes:
    """Собирает потоковый ответ целиком: magic + записи [2B len][AESGCM(кадр)].
    Используется в тестах; на проде ответ стримится по частям, чтобы не держать
    в памяти весь ответ (лечит OOM на больших закачках)."""
    out = bytearray(RESP_STREAM_MAGIC)
    for plain in iter_stream_records(frames):
        rec = encrypt(enc_key, plain)
        out += struct.pack("!H", len(rec)) + rec
    return bytes(out)


# ── Фейковый контент для повторных / невалидных запросов ──────────────
# Если запрос не прошёл проверку протокола (повтор из истории CDN, отсутствие
# параметров, устаревший timestamp), мы НЕ отдаём ошибки протокола (missing
# params / bad mac / stale) — они палят туннель. Вместо этого отвечаем
# правдоподобным контентом под тип URL (js/css/json/картинка и т.п.), а для
# всего остального — HTML-заглушкой 404. Ошибки протокола доступны только при
# заголовке X-Debug: 1 (диагностика своего клиента).

TINY_PNG = (
    b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
    b"\x08\x06\x00\x00\x00\x1f\x15\xc4\x89\x00\x00\x00\rIDATx\x9cc\xf8\x7f"
    b"\x1f\x00\x07\x06\x01\x80/\x9e\x17\x00\x00\x00\x00IEND\xaeB`\x82"
)

_FAKE_TEXT = {
    "application/javascript; charset=utf-8": (
        "/* __g.rev 2026.08.14 */\n"
        "var __g={rev:1,cache:true,ready:false};\n"
        "function __ready(f){if(document.readyState!=='loading')f();"
        "else document.addEventListener('DOMContentLoaded',f)}\n"
        "__ready(function(){__g.ready=true});\n"
    ),
    "text/css; charset=utf-8": (
        ":root{--a:#3b82f6}\n*{box-sizing:border-box}\n"
        "html,body{margin:0;height:100%}\n"
        "body{font:15px/1.5 system-ui,Segoe UI,Roboto,sans-serif;"
        "background:#f8fafc;color:#0f172a}\n"
    ),
    "application/json; charset=utf-8": '{"ok":true,"version":1,"status":"OK","data":[]}\n',
    "application/xml; charset=utf-8": '<?xml version="1.0" encoding="UTF-8"?><root><status>OK</status></root>\n',
    "text/plain; charset=utf-8": "OK\n",
    "application/vnd.apple.mpegurl": (
        "#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-TARGETDURATION:6\n"
        "#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:6.0,\n/media/segment001.ts\n"
        "#EXTINF:6.0,\n/media/segment002.ts\n#EXT-X-ENDLIST\n"
    ),
    "image/svg+xml": (
        '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 16 16">'
        '<rect width="16" height="16" fill="#e2e8f0"/></svg>\n'
    ),
}

# Расширение (нижний регистр, с точкой) -> content-type
_FAKE_EXT = {
    ".js": "application/javascript; charset=utf-8",
    ".mjs": "application/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".json": "application/json; charset=utf-8",
    ".xml": "application/xml; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".svg": "image/svg+xml",
    ".m3u8": "application/vnd.apple.mpegurl",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".webp": "image/webp",
    ".avif": "image/avif",
    ".ico": "image/x-icon",
    ".woff": "font/woff",
    ".woff2": "font/woff2",
    ".ttf": "font/ttf",
    ".otf": "font/otf",
    ".mp4": "video/mp4",
    ".webm": "video/webm",
    ".mkv": "video/x-matroska",
    ".ts": "video/mp2t",
    ".mp3": "audio/mpeg",
    ".ogg": "audio/ogg",
    ".m4a": "audio/mp4",
    ".aac": "audio/aac",
    ".wav": "audio/wav",
    ".zip": "application/zip",
    ".gz": "application/gzip",
    ".tar": "application/x-tar",
    ".apk": "application/vnd.android.package-archive",
    ".pdf": "application/pdf",
    ".exe": "application/octet-stream",
    ".bin": "application/octet-stream",
}

_FAKE_JSON_PREFIXES = (
    "/api/", "/config", "/health", "/status", "/manifest",
    "/locales/", "/i18n/", "/edge/", "/cdn/config", "/content/",
)


def fake_response(request) -> web.Response:
    """Возвращает правдоподобный ответ под тип URL; иначе 404-заглушку."""
    path = request.path.lower()
    for prefix in _FAKE_JSON_PREFIXES:
        if path.startswith(prefix):
            ct = "application/json"
            return web.Response(body=_FAKE_TEXT["application/json; charset=utf-8"].encode(),
                                headers={"Content-Type": ct, "Cache-Control": "public, max-age=3600"})
    for ext, ct in _FAKE_EXT.items():
        if path.endswith(ext):
            body = _FAKE_TEXT.get(ct, TINY_PNG)
            if isinstance(body, str):
                body = body.encode()
            return web.Response(body=body,
                                headers={"Content-Type": ct, "Cache-Control": "public, max-age=3600"})
    return web.Response(
        status=404,
        headers={"Content-Type": "text/html; charset=utf-8"},
        body=('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
              '<title>404 Not Found</title></head><body><center>'
              '<h1>404 Not Found</h1><p>The requested URL was not found on '
              'this server.</p></center></body></html>'),
    )


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


class ServerSession:
    def __init__(self, session_id: bytes, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.writer = writer
        self.reader: asyncio.StreamReader | None = None
        self.incoming = bytearray()
        self.seq = 0
        self.fin_pending = False
        self.closed = False
        self.pump_task: asyncio.Task | None = None

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def close(self) -> None:
        """Полностью закрывает сессию: отменяет пум-таск и сокет, чтобы
        не копить FD/таски/буферы при клиентском FIN или реапе."""
        self.closed = True
        if self.pump_task is not None and not self.pump_task.done():
            self.pump_task.cancel()
        try:
            self.writer.close()
        except Exception:
            pass


class SessionManager:
    def __init__(self, max_chunk_bytes: int, idle_timeout: int, dns_resolver: str = "8.8.8.8",
                 dns_port: int = 53):
        self.clients: dict = {}   # client_id -> {session_id: ServerSession}
        self.last_seen: dict = {}  # client_id -> monotonic timestamp
        self.lock = asyncio.Lock()
        self.max_chunk_bytes = max_chunk_bytes
        self._incoming_cap = max_chunk_bytes * 2  # мягкий предел буфера сессии (backpressure)
        self._pending_data_cap = max_chunk_bytes * 16  # предел накопления данных для pending-сессии
        self.idle_timeout = idle_timeout
        self._pending_opens: dict[bytes, set[bytes]] = {}
        self._pending_data: dict[bytes, dict[bytes, list[bytes]]] = {}
        self._dns_replies: dict[bytes, dict[bytes, bytes]] = {}  # client_id -> {sid: dns_response}
        # Резолверы перебираются по порядку при таймауте/ошибке. 8.8.8.8 молча
        # дропает запросы с EDNS0-паддингом (шлёт happ DoU), 1.1.1.1 отвечает.
        self._dns_resolvers = [(host.strip(), int(port)) for host, port in
                               self._parse_resolvers(dns_resolver, dns_port)]

    @staticmethod
    def _parse_resolvers(dns_resolver: str, dns_port: int):
        """Принимает '8.8.8.8' или '8.8.8.8:53,1.1.1.1:53'."""
        items = [part.strip() for part in dns_resolver.split(",") if part.strip()]
        for part in items:
            if ":" in part:
                h, p = part.rsplit(":", 1)
                try:
                    yield h.strip(), int(p)
                except ValueError:
                    yield part, dns_port
            else:
                yield part, dns_port
        if not items:
            yield dns_resolver, dns_port

    async def handle_incoming(self, client_id: bytes, frames):
        cid = client_id.hex()[:8]
        async with self.lock:
            self.last_seen[client_id] = time.monotonic()
            self.clients.setdefault(client_id, {})

        logger.debug(f"[server] handling {len(frames)} frames from client {cid}")
        for f in frames:
            sid = f.session_id.hex()[:8]
            if f.flags & FLAG_NEW:
                host, port = f.parse_new_target()
                logger.info(f"[server] NEW: client {cid} -> session {sid} (target {host}:{port})")
                async with self.lock:
                    self._pending_opens.setdefault(client_id, set()).add(f.session_id)
                asyncio.create_task(self._open_remote(client_id, f.session_id, host, port))
            elif f.flags & FLAG_DNS:
                logger.debug(f"[server] DNS: client {cid} query {len(f.payload)}B (sid {sid})")
                asyncio.create_task(self._resolve_dns(client_id, f.session_id, f.payload))
            elif f.flags & FLAG_DATA:
                async with self.lock:
                    sess = self.clients.get(client_id, {}).get(f.session_id)
                if sess is not None and not sess.closed:
                    try:
                        logger.debug(f"[server] DATA: session {sid} writing {len(f.payload)} bytes to remote")
                        sess.writer.write(f.payload)
                        await sess.writer.drain()
                    except Exception as e:
                        logger.error(f"[server] session {sid} write failed: {e}")
                        sess.closed = True
                else:
                    async with self.lock:
                        if client_id in self._pending_opens and f.session_id in self._pending_opens[client_id]:
                            buf = self._pending_data.setdefault(client_id, {}).setdefault(f.session_id, [])
                            used = sum(len(b) for b in buf if b is not None)
                            if used + len(f.payload) > self._pending_data_cap:
                                logger.warning(f"[server] DATA: dropping {len(f.payload)}B, pending session {sid} buffer full")
                            else:
                                buf.append(f.payload)
                                logger.debug(f"[server] DATA: buffered {len(f.payload)} bytes for pending session {sid}")
                        else:
                            logger.warning(f"[server] DATA: session {sid} not found or closed")
            elif f.flags & FLAG_FIN:
                logger.info(f"[server] FIN: session {sid}")
                async with self.lock:
                    sess = self.clients.get(client_id, {}).get(f.session_id)
                if sess is not None:
                    sess.close()
                else:
                    async with self.lock:
                        if client_id in self._pending_opens and f.session_id in self._pending_opens[client_id]:
                            self._pending_data.setdefault(client_id, {}).setdefault(f.session_id, []).append(None)
                            logger.debug(f"[server] FIN: buffered for pending session {sid}")

    async def _open_remote(self, client_id: bytes, session_id: bytes, host: str, port: int):
        logger.debug(f"[server] attempting to connect to {host}:{port}")
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=10)
        except asyncio.TimeoutError:
            logger.error(f"[server] timeout connecting to {host}:{port}")
            self._cleanup_pending(client_id, session_id)
            return
        except Exception as e:
            logger.error(f"[server] connect to {host}:{port} failed: {e}")
            self._cleanup_pending(client_id, session_id)
            return
        sess = ServerSession(session_id, writer)
        sess.reader = reader
        enable_tcp_keepalive(writer.transport)

        buffered = []
        async with self.lock:
            self.clients.setdefault(client_id, {})[session_id] = sess
            self._cleanup_pending_locked(client_id, session_id)
            buffered = self._pending_data.get(client_id, {}).pop(session_id, [])

        logger.debug(f"[server] opened remote {host}:{port} for session {session_id.hex()[:8]}")

        if buffered:
            for data in buffered:
                if data is None:
                    logger.info(f"[server] closing session immediately (FIN was buffered)")
                    sess.closed = True
                    try:
                        sess.writer.close()
                    except Exception:
                        pass
                    return
                sess.writer.write(data)
            try:
                await sess.writer.drain()
                logger.debug(f"[server] flushed {len(buffered)} buffered frames for session {session_id.hex()[:8]}")
            except Exception as e:
                logger.error(f"[server] flush failed for session {session_id.hex()[:8]}: {e}")

        sess.pump_task = asyncio.create_task(self._pump_remote_to_buffer(reader, sess))
        return sess

    def _cleanup_pending_locked(self, client_id: bytes, session_id: bytes):
        if client_id in self._pending_opens:
            self._pending_opens[client_id].discard(session_id)
            if not self._pending_opens[client_id]:
                del self._pending_opens[client_id]

    async def _cleanup_pending(self, client_id: bytes, session_id: bytes):
        async with self.lock:
            self._cleanup_pending_locked(client_id, session_id)
            self._pending_data.get(client_id, {}).pop(session_id, None)

    async def _pump_remote_to_buffer(self, reader: asyncio.StreamReader, sess: ServerSession):
        sid = sess.session_id.hex()[:8]
        try:
            while True:
                # Backpressure: не читаем из remote, пока клиент не забрал
                # накопленное — иначе буфер сессии растёт безгранично (OOM).
                while True:
                    async with self.lock:
                        full = len(sess.incoming) > self._incoming_cap
                    if not full:
                        break
                    await asyncio.sleep(0.05)
                data = await reader.read(self.max_chunk_bytes)
                if not data:
                    logger.debug(f"[server] session {sid} got EOF from remote")
                    break
                logger.debug(f"[server] pump: session {sid} buffered {len(data)} bytes from remote")
                async with self.lock:
                    sess.incoming.extend(data)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"[server] pump error for session {sid}: {e}")
        finally:
            async with self.lock:
                sess.fin_pending = True
            logger.debug(f"[server] pump finished for session {sid}")

    async def _resolve_dns(self, client_id: bytes, session_id: bytes, query: bytes):
        """Резолвит raw DNS-запрос через резолверы (с fallback) и кладёт ответ в outbox клиента."""
        loop = asyncio.get_event_loop()
        last_error = None
        for host, port in self._dns_resolvers:
            fut = loop.create_future()

            class _Proto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not fut.done():
                        fut.set_result(data)

                def error_received(self, exc):
                    if not fut.done():
                        fut.set_exception(exc)

            transport = None
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda: _Proto(),
                    remote_addr=(host, port),
                )
                transport.sendto(query)
                reply = await asyncio.wait_for(fut, timeout=4)
            except Exception as e:
                last_error = e
                if transport is not None:
                    transport.close()
                continue
            finally:
                if transport is not None:
                    transport.close()

            if reply and len(reply) >= 12:
                async with self.lock:
                    self._dns_replies.setdefault(client_id, {})[session_id] = reply
                logger.debug(f"[server] DNS reply {len(reply)}B stored for sid {session_id.hex()[:8]}")
                return
            last_error = ValueError(f"bad reply len {len(reply) if reply else 0}")
        logger.error(f"[server] DNS resolve failed for sid {session_id.hex()[:8]}: {last_error}")

    async def collect_outgoing(self, client_id: bytes):
        frames = []
        async with self.lock:
            dns_replies = self._dns_replies.pop(client_id, {})
            for sid, payload in dns_replies.items():
                frames.append(Frame(sid, 0, FLAG_DNS, payload))
            sessions = self.clients.get(client_id, {})
            dead = []
            for sid, sess in sessions.items():
                if sess.incoming:
                    chunk = bytes(sess.incoming[: self.max_chunk_bytes])
                    del sess.incoming[: len(chunk)]
                    frames.append(Frame(sid, sess.next_seq(), FLAG_DATA, chunk))
                if sess.fin_pending and not sess.incoming:
                    frames.append(Frame(sid, sess.next_seq(), FLAG_FIN, b""))
                    dead.append(sid)
                elif sess.closed and not sess.incoming:
                    dead.append(sid)
            for sid in dead:
                del sessions[sid]
        return frames

    async def reap_idle_clients(self):
        """Периодически закрывает все сессии клиентов, которые давно не опрашивали сервер."""
        while True:
            await asyncio.sleep(30)
            now = time.monotonic()
            async with self.lock:
                stale = [cid for cid, t in self.last_seen.items() if now - t > self.idle_timeout]
                for cid in stale:
                    clients_sessions = self.clients.pop(cid, {})
                    for sess in clients_sessions.values():
                        sess.close()
                    # Полная очистка всего состояния клиента (пум-таски и сокеты уже
                    # закрыты в close(); чистим и pending-буферы, чтобы не копить память).
                    self._pending_opens.pop(cid, None)
                    self._pending_data.pop(cid, None)
                    self._dns_replies.pop(cid, None)
                    self.last_seen.pop(cid, None)
                    logger.info("reaped idle client %s", cid.hex()[:8])


async def poll_handler(request: web.Request):
    app = request.app
    debug = request.headers.get("X-Debug") == "1"
    qs = request.query
    ts = qs.get("t")
    cid_b64 = request.headers.get("X-Cid")
    mac = request.headers.get("X-Mac")

    # Каждый poll-запрос — это низкоуровневый шум (клиент опрашивает ~5-20 раз/с).
    # В INFO он не попадёт: это детальная отладка, доступная только в DEBUG.
    logger.debug("poll: method=%s path=%s ts=%s cid=%s mac=%s",
                 request.method, request.path, ts, cid_b64, bool(mac))

    if not all([cid_b64, ts, mac]):
        if debug:
            logger.warning("400 missing params: cid=%s ts=%s mac=%s", cid_b64 is not None, ts, mac is not None)
            return web.Response(status=400, text="missing params")
        return fake_response(request)

    read_body = await request.read()
    d_b64 = request.headers.get("X-Data")
    if not d_b64:
        d_b64 = read_body.decode()
    if not d_b64:
        d_b64 = qs.get("d")
    if not d_b64:
        if debug:
            logger.warning("400 missing data: cid=%s ts=%s X-Data=%s body_len=%s",
                           cid_b64, ts, bool(request.headers.get("X-Data")), len(read_body))
            return web.Response(status=400, text="missing data")
        return fake_response(request)

    try:
        client_id = b64u_decode(cid_b64)
        blob = b64u_decode(d_b64)
    except Exception as e:
        if debug:
            logger.warning("400 bad encoding: %s", e)
            return web.Response(status=400, text="bad encoding")
        return fake_response(request)

    hmac_key = app["hmac_key"]
    if not verify(hmac_key, client_id + ts.encode() + blob, mac):
        if debug:
            from crypto_utils import sign as _sign
            expected = _sign(hmac_key, client_id + ts.encode() + blob)
            logger.warning("403 bad mac: cid=%s ts=%s blob_len=%s d64_len=%s "
                           "got_mac=%s expected_mac=%s",
                           cid_b64, ts, len(blob), len(d_b64), mac, expected)
            return web.Response(status=403, text="bad mac")
        return fake_response(request)

    window = app["hmac_window_seconds"]
    try:
        ts_int = int(ts)
    except ValueError:
        if debug:
            logger.warning("400 bad timestamp: ts=%s", ts)
            return web.Response(status=400, text="bad timestamp")
        return fake_response(request)
    diff = abs(int(time.time()) - ts_int)
    if diff > window:
        if debug:
            logger.warning("403 stale request: ts=%s now=%s diff=%ss window=%ss", ts, int(time.time()), diff, window)
            return web.Response(status=403, text="stale request")
        return fake_response(request)

    enc_key = app["enc_key"]
    try:
        plaintext = decrypt(enc_key, blob)
        frames = unpack_frames(plaintext)
    except Exception as e:
        if debug:
            logger.warning("400 bad payload: %s", e)
            return web.Response(status=400, text="bad payload")
        return fake_response(request)

    mgr: SessionManager = app["session_mgr"]
    await mgr.handle_incoming(client_id, frames)
    out_frames = await mgr.collect_outgoing(client_id)

    if request.headers.get("X-Proto", "1") == PROTO_VERSION:
        # Потоковый формат: magic + независимо зашифрованные рекорды.
        # Стримим по частям с заранее известным Content-Length, чтобы не держать
        # весь ответ в памяти (OOM на больших закачках при 1GB RAM сервера).
        total = len(RESP_STREAM_MAGIC) + sum(
            2 + len(plain) + AES_GCM_OVERHEAD for plain in iter_stream_records(out_frames)
        )
        resp = web.StreamResponse(status=200)
        resp.content_type = "application/octet-stream"
        resp.content_length = total
        await resp.prepare(request)
        await resp.write(RESP_STREAM_MAGIC)
        for plain in iter_stream_records(out_frames):
            rec = encrypt(enc_key, plain)
            await resp.write(struct.pack("!H", len(rec)) + rec)
        return resp

    resp_batch = pack_frames(out_frames)
    resp_blob = encrypt(enc_key, resp_batch)
    # Content-Length ставится aiohttp автоматически по длине body — ответ всегда
    # имеет заранее известную длину, никакого chunked transfer encoding.
    return web.Response(body=resp_blob, content_type="application/octet-stream")


def build_app(cfg: dict) -> web.Application:
    sec_cfg = cfg["security"]
    server_cfg = cfg["server"]

    # aiohttp по умолчанию отклоняет тела запросов > 1MB (413). Клиент шлёт
    # исходящие данные (до max_chunk_bytes на сессию, base64+шифрование ~1.5x)
    # в теле poll-запроса — поднимаем лимит с запасом на несколько сессий.
    max_chunk = int(server_cfg.get("max_chunk_bytes", 4096))
    client_max = max(max_chunk * 3, 16 * 1024 * 1024)

    app = web.Application(client_max_size=client_max)
    app["enc_key"] = derive_key(sec_cfg["psk"])
    app["hmac_key"] = derive_hmac_key(sec_cfg["psk"])
    app["hmac_window_seconds"] = int(sec_cfg.get("hmac_window_seconds", 30))
    app["session_mgr"] = SessionManager(
        max_chunk_bytes=int(server_cfg.get("max_chunk_bytes", 4096)),
        idle_timeout=int(server_cfg.get("idle_timeout_seconds", 120)),
        dns_resolver=str(server_cfg.get("dns_resolver", "8.8.8.8:53,1.1.1.1:53")),
        dns_port=int(server_cfg.get("dns_resolver_port", 53)),
    )
    poll_path = server_cfg.get("poll_path", "/poll")
    app.router.add_route("GET", poll_path, poll_handler)
    app.router.add_route("POST", poll_path, poll_handler)
    # Клиент генерирует случайное "CDN-образное" продолжение пути поверх poll_path.
    # Принимаем любой путь как poll-хендлер (наиболее специфичные маршруты выше
    # имеют приоритет, этот catch-all ловит всё остальное).
    app.router.add_route("GET", "/{tail:.*}", poll_handler)
    app.router.add_route("POST", "/{tail:.*}", poll_handler)

    async def _start_background(app):
        app["reaper_task"] = asyncio.create_task(app["session_mgr"].reap_idle_clients())

    async def _stop_background(app):
        app["reaper_task"].cancel()

    app.on_startup.append(_start_background)
    app.on_cleanup.append(_stop_background)
    return app


def run_server(cfg: dict):
    server_cfg = cfg["server"]
    app = build_app(cfg)

    ssl_context = None
    tls_cfg = server_cfg.get("tls")
    if tls_cfg and tls_cfg.get("cert") and tls_cfg.get("key"):
        import ssl
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(tls_cfg["cert"], tls_cfg["key"])
    else:
        logger.warning("TLS not configured — running plain HTTP (only for local testing!)")

    web.run_app(app, host=server_cfg["bind_host"], port=server_cfg["bind_port"], ssl_context=ssl_context)