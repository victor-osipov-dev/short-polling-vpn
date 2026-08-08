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
import time

from aiohttp import web

from protocol import (
    Frame, FLAG_NEW, FLAG_DATA, FLAG_FIN, FLAG_DNS,
    pack_frames, unpack_frames,
)
from crypto_utils import (
    derive_key, derive_hmac_key, encrypt, decrypt, verify,
    b64u_encode, b64u_decode,
)

logger = logging.getLogger("vpn-server")


class ServerSession:
    def __init__(self, session_id: bytes, writer: asyncio.StreamWriter):
        self.session_id = session_id
        self.writer = writer
        self.incoming = bytearray()
        self.seq = 0
        self.fin_pending = False
        self.closed = False

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq


class SessionManager:
    def __init__(self, max_chunk_bytes: int, idle_timeout: int, dns_resolver: str = "8.8.8.8",
                 dns_port: int = 53):
        self.clients: dict = {}   # client_id -> {session_id: ServerSession}
        self.last_seen: dict = {}  # client_id -> monotonic timestamp
        self.lock = asyncio.Lock()
        self.max_chunk_bytes = max_chunk_bytes
        self.idle_timeout = idle_timeout
        self._pending_opens: dict[bytes, set[bytes]] = {}
        self._pending_data: dict[bytes, dict[bytes, list[bytes]]] = {}
        self._dns_replies: dict[bytes, dict[bytes, bytes]] = {}  # client_id -> {sid: dns_response}
        self._dns_resolver_host = dns_resolver
        self._dns_resolver_port = dns_port

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
                logger.info(f"[server] DNS: client {cid} query {len(f.payload)}B (sid {sid})")
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
                            self._pending_data.setdefault(client_id, {}).setdefault(f.session_id, []).append(f.payload)
                            logger.debug(f"[server] DATA: buffered {len(f.payload)} bytes for pending session {sid}")
                        else:
                            logger.warning(f"[server] DATA: session {sid} not found or closed")
            elif f.flags & FLAG_FIN:
                logger.info(f"[server] FIN: session {sid}")
                async with self.lock:
                    sess = self.clients.get(client_id, {}).get(f.session_id)
                if sess is not None:
                    sess.closed = True
                    try:
                        sess.writer.close()
                    except Exception:
                        pass
                else:
                    async with self.lock:
                        if client_id in self._pending_opens and f.session_id in self._pending_opens[client_id]:
                            self._pending_data.setdefault(client_id, {}).setdefault(f.session_id, []).append(None)
                            logger.debug(f"[server] FIN: buffered for pending session {sid}")

    async def _open_remote(self, client_id: bytes, session_id: bytes, host: str, port: int):
        logger.info(f"[server] attempting to connect to {host}:{port}")
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

        buffered = []
        async with self.lock:
            self.clients.setdefault(client_id, {})[session_id] = sess
            self._cleanup_pending_locked(client_id, session_id)
            buffered = self._pending_data.get(client_id, {}).pop(session_id, [])

        logger.info(f"[server] opened remote {host}:{port} for session {session_id.hex()[:8]}")

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
                logger.info(f"[server] flushed {len(buffered)} buffered frames for session {session_id.hex()[:8]}")
            except Exception as e:
                logger.error(f"[server] flush failed for session {session_id.hex()[:8]}: {e}")

        asyncio.create_task(self._pump_remote_to_buffer(reader, sess))

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
                try:
                    data = await asyncio.wait_for(reader.read(self.max_chunk_bytes), timeout=30)
                except asyncio.TimeoutError:
                    logger.debug(f"[server] pump timeout for session {sid}")
                    break
                if not data:
                    logger.info(f"[server] session {sid} got EOF from remote")
                    break
                logger.debug(f"[server] pump: session {sid} buffered {len(data)} bytes from remote")
                async with self.lock:
                    sess.incoming.extend(data)
        except Exception as e:
            logger.error(f"[server] pump error for session {sid}: {e}")
        finally:
            sess.fin_pending = True
            logger.info(f"[server] pump finished for session {sid}")

    async def _resolve_dns(self, client_id: bytes, session_id: bytes, query: bytes):
        """Резолвит raw DNS-запрос через dns_resolver и кладёт ответ в outbox клиента."""
        try:
            loop = asyncio.get_event_loop()
            fut = loop.create_future()

            class _Proto(asyncio.DatagramProtocol):
                def datagram_received(self, data, addr):
                    if not fut.done():
                        fut.set_result(data)

                def error_received(self, exc):
                    if not fut.done():
                        fut.set_exception(exc)

            transport, _ = await loop.create_datagram_endpoint(
                lambda: _Proto(),
                remote_addr=(self._dns_resolver_host, self._dns_resolver_port),
            )
            try:
                transport.sendto(query)
                reply = await asyncio.wait_for(fut, timeout=10)
            finally:
                transport.close()
        except Exception as e:
            logger.error(f"[server] DNS resolve failed for sid {session_id.hex()[:8]}: {e}")
            return

        if len(reply) < 12 or not reply:
            logger.warning(f"[server] DNS bad reply for sid {session_id.hex()[:8]}: {len(reply)}B")
            return
        async with self.lock:
            self._dns_replies.setdefault(client_id, {})[session_id] = reply
        logger.debug(f"[server] DNS reply {len(reply)}B stored for sid {session_id.hex()[:8]}")

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
                    for sess in self.clients.get(cid, {}).values():
                        try:
                            sess.writer.close()
                        except Exception:
                            pass
                    self.clients.pop(cid, None)
                    self.last_seen.pop(cid, None)
                    self._dns_replies.pop(cid, None)
                    logger.info("reaped idle client %s", cid.hex()[:8])


async def poll_handler(request: web.Request):
    app = request.app
    qs = request.query
    ts = qs.get("t")
    cid_b64 = request.headers.get("X-Cid")
    mac = request.headers.get("X-Mac")

    logger.info("poll: method=%s path=%s ts=%s cid=%s mac=%s hdrs=%s",
                request.method, request.path, ts, cid_b64,
                bool(mac), dict(request.headers))

    if not all([cid_b64, ts, mac]):
        logger.warning("400 missing params: cid=%s ts=%s mac=%s", cid_b64 is not None, ts, mac is not None)
        return web.Response(status=400, text="missing params")

    read_body = await request.read()
    d_b64 = request.headers.get("X-Data")
    if not d_b64:
        d_b64 = read_body.decode()
    if not d_b64:
        d_b64 = qs.get("d")
    if not d_b64:
        logger.warning("400 missing data: cid=%s ts=%s X-Data=%s body_len=%s",
                       cid_b64, ts, bool(request.headers.get("X-Data")), len(read_body))
        return web.Response(status=400, text="missing data")

    try:
        client_id = b64u_decode(cid_b64)
        blob = b64u_decode(d_b64)
    except Exception as e:
        logger.warning("400 bad encoding: %s", e)
        return web.Response(status=400, text="bad encoding")

    hmac_key = app["hmac_key"]
    if not verify(hmac_key, client_id + ts.encode() + blob, mac):
        from crypto_utils import sign as _sign
        expected = _sign(hmac_key, client_id + ts.encode() + blob)
        logger.warning("403 bad mac: cid=%s ts=%s blob_len=%s d64_len=%s "
                       "got_mac=%s expected_mac=%s",
                       cid_b64, ts, len(blob), len(d_b64), mac, expected)
        return web.Response(status=403, text="bad mac")

    window = app["hmac_window_seconds"]
    try:
        ts_int = int(ts)
    except ValueError:
        logger.warning("400 bad timestamp: ts=%s", ts)
        return web.Response(status=400, text="bad timestamp")
    diff = abs(int(time.time()) - ts_int)
    if diff > window:
        logger.warning("403 stale request: ts=%s now=%s diff=%ss window=%ss", ts, int(time.time()), diff, window)
        return web.Response(status=403, text="stale request")

    enc_key = app["enc_key"]
    try:
        plaintext = decrypt(enc_key, blob)
        frames = unpack_frames(plaintext)
    except Exception as e:
        logger.warning("400 bad payload: %s", e)
        return web.Response(status=400, text="bad payload")

    mgr: SessionManager = app["session_mgr"]
    await mgr.handle_incoming(client_id, frames)
    out_frames = await mgr.collect_outgoing(client_id)

    resp_batch = pack_frames(out_frames)
    resp_blob = encrypt(enc_key, resp_batch)
    # Content-Length ставится aiohttp автоматически по длине body — ответ всегда
    # имеет заранее известную длину, никакого chunked transfer encoding.
    return web.Response(body=resp_blob, content_type="application/octet-stream")


def build_app(cfg: dict) -> web.Application:
    sec_cfg = cfg["security"]
    server_cfg = cfg["server"]

    app = web.Application()
    app["enc_key"] = derive_key(sec_cfg["psk"])
    app["hmac_key"] = derive_hmac_key(sec_cfg["psk"])
    app["hmac_window_seconds"] = int(sec_cfg.get("hmac_window_seconds", 30))
    app["session_mgr"] = SessionManager(
        max_chunk_bytes=int(server_cfg.get("max_chunk_bytes", 4096)),
        idle_timeout=int(server_cfg.get("idle_timeout_seconds", 120)),
        dns_resolver=str(server_cfg.get("dns_resolver", "8.8.8.8")),
        dns_port=int(server_cfg.get("dns_resolver_port", 53)),
    )
    poll_path = server_cfg.get("poll_path", "/poll")
    app.router.add_route("GET", poll_path, poll_handler)
    app.router.add_route("POST", poll_path, poll_handler)

    async def stub_handler(request):
        return web.Response(
            content_type="text/html",
            charset="utf-8",
            body="""<!DOCTYPE html>
<html lang="ru">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Short Polling VPN</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
  background:linear-gradient(135deg,#0f0c29,#302b63,#24243e);min-height:100vh;
  display:flex;align-items:center;justify-content:center;color:#fff}
.card{background:rgba(255,255,255,.08);backdrop-filter:blur(12px);
  border-radius:24px;padding:48px 40px;text-align:center;max-width:440px;
  box-shadow:0 25px 50px -12px rgba(0,0,0,.5);border:1px solid rgba(255,255,255,.1)}
h1{font-size:28px;font-weight:600;margin-bottom:8px}
p{color:rgba(255,255,255,.7);font-size:15px;line-height:1.6;margin-bottom:24px}
.status{display:inline-flex;align-items:center;gap:8px;
  background:rgba(34,197,94,.15);color:#4ade80;border:1px solid rgba(34,197,94,.3);
  border-radius:999px;padding:6px 18px;font-size:14px;font-weight:500}
.status::before{content:'';width:8px;height:8px;border-radius:50%;background:#22c55e;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
</style></head>
<body><div class="card">
<h1>Short Polling VPN</h1>
<p>This server is running a secure tunnel proxy.<br>
Direct access is disabled for security reasons.</p>
<div class="status">Service active</div>
</div></body>
</html>""",
        )

    app.router.add_get("/{tail:.*}", stub_handler)

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