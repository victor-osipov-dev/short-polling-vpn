"""
Short Polling VPN engine – adapted for Android + Chaquopy.
Protocol, crypto, SOCKS5 server, and polling loop in one file.
Config is read from JSON (passed by Kotlin via CONFIG_PATH env or default path).
"""

import asyncio
import hashlib
import hmac as hmac_mod
import json
import logging
import os
import random
import socket
import struct
import sys
import time
import threading

import httpx

logger = logging.getLogger("proxy")

# ── Protocol ──────────────────────────────────────────────────────────

FLAG_NEW = 1
FLAG_DATA = 2
FLAG_FIN = 4
SESSION_ID_LEN = 16
_FRAME_HEADER_FMT = "!16sIBI"
_FRAME_HEADER_LEN = struct.calcsize(_FRAME_HEADER_FMT)


class Frame:
    __slots__ = ("session_id", "seq", "flags", "payload")

    def __init__(self, session_id: bytes, seq: int, flags: int, payload: bytes = b""):
        if len(session_id) != SESSION_ID_LEN:
            raise ValueError("session_id must be 16 bytes")
        self.session_id = session_id
        self.seq = seq
        self.flags = flags
        self.payload = payload

    def encode(self) -> bytes:
        return struct.pack(_FRAME_HEADER_FMT, self.session_id,
                           self.seq & 0xFFFFFFFF, self.flags, len(self.payload)) + self.payload

    @classmethod
    def decode(cls, data: bytes, offset: int = 0):
        if offset + _FRAME_HEADER_LEN > len(data):
            raise ValueError("truncated frame header")
        sid, seq, flags, plen = struct.unpack_from(_FRAME_HEADER_FMT, data, offset)
        offset += _FRAME_HEADER_LEN
        if offset + plen > len(data):
            raise ValueError("truncated frame payload")
        payload = data[offset:offset + plen]
        offset += plen
        return cls(sid, seq, flags, payload), offset

    @classmethod
    def new_frame(cls, session_id: bytes, seq: int, host: str, port: int):
        host_b = host.encode()
        if len(host_b) > 255:
            raise ValueError("host too long")
        payload = struct.pack("!B", len(host_b)) + host_b + struct.pack("!H", port)
        return cls(session_id, seq, FLAG_NEW, payload)

    def parse_new_target(self):
        hl = self.payload[0]
        host = self.payload[1:1 + hl].decode()
        port = struct.unpack_from("!H", self.payload, 1 + hl)[0]
        return host, port


def pack_frames(frames) -> bytes:
    out = bytearray(struct.pack("!H", len(frames)))
    for f in frames:
        out += f.encode()
    return bytes(out)


def unpack_frames(data: bytes):
    if len(data) < 2:
        return []
    count = struct.unpack_from("!H", data, 0)[0]
    offset = 2
    frames = []
    for _ in range(count):
        f, offset = Frame.decode(data, offset)
        frames.append(f)
    return frames


def new_session_id() -> bytes:
    return os.urandom(SESSION_ID_LEN)

# ── Crypto ────────────────────────────────────────────────────────────

def derive_key(psk: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    raw = base64.b64decode(psk)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vpn-poller-enc")
    return hkdf.derive(raw)

def derive_hmac_key(psk: str) -> bytes:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    raw = base64.b64decode(psk)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"vpn-poller-hmac")
    return hkdf.derive(raw)

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def decrypt(key: bytes, ciphertext: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce, ct = ciphertext[:12], ciphertext[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None)

def sign(key: bytes, data: bytes) -> str:
    return hmac_mod.new(key, data, "sha256").hexdigest()

def verify(key: bytes, data: bytes, sig: str) -> bool:
    return hmac_mod.new(key, data, "sha256").hexdigest() == sig

def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "==")

import base64

# ── Client Tunnel ─────────────────────────────────────────────────────

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
        self.server_base = client_cfg["server_url"].rstrip("/")
        self.poll_path = client_cfg.get("poll_path", "/poll")
        self.server_url = self.server_base + self.poll_path
        self.poll_interval_ms = int(client_cfg.get("poll_interval_ms", 200))
        self.poll_jitter_ms = int(client_cfg.get("poll_jitter_ms", 50))
        self.max_chunk_bytes = int(client_cfg.get("max_chunk_bytes", 4096))
        self.poll_method = client_cfg.get("poll_method", "POST").upper()
        self.poll_data_in = client_cfg.get("poll_data_in", "body")
        self.host_header = client_cfg.get("host_header") or None
        verify_tls = client_cfg.get("verify_tls", True)

        self.enc_key = derive_key(sec_cfg["psk"].strip())
        self.hmac_key = derive_hmac_key(sec_cfg["psk"].strip())

        idle_cfg = client_cfg.get("idle_timeout", {})
        self.idle_timeout_enabled = idle_cfg.get("enabled", False)
        self.idle_timeout_seconds = int(idle_cfg.get("seconds", 300))
        self._last_activity = time.monotonic()
        self._idle_logged = False

        self.sessions: dict = {}
        self.lock = asyncio.Lock()
        self.http = httpx.AsyncClient(http2=True, verify=verify_tls, timeout=15.0)
        self._stop = False
        self._on_log = None
        self.time_offset = 0

    def set_log_callback(self, cb):
        self._on_log = cb

    def log(self, msg: str):
        if self._on_log:
            self._on_log(msg)
        else:
            logger.info(msg)

    async def register_session(self, writer: asyncio.StreamWriter, host: str, port: int) -> bytes:
        sid = new_session_id()
        sess = ClientSession(sid, writer)
        frame = Frame.new_frame(sid, sess.next_seq(), host, port)
        sess.pending_new = frame
        async with self.lock:
            self.sessions[sid] = sess
        self._last_activity = time.monotonic()
        self.log(f"new session {sid.hex()[:8]} -> {host}:{port}")
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

    async def poll_loop(self):
        while not self._stop:
            if self.idle_timeout_enabled:
                idle_elapsed = time.monotonic() - self._last_activity
                if idle_elapsed >= self.idle_timeout_seconds:
                    if not self._idle_logged:
                        self.log(f"idle timeout ({self.idle_timeout_seconds}s): pausing polls")
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
                    self.log("activity resumed, resuming polls")
                    self._idle_logged = False
            try:
                await self._poll_once()
            except Exception as e:
                logger.warning(f"poll error: {e}")
            jitter = random.randint(-self.poll_jitter_ms, self.poll_jitter_ms)
            delay_ms = max(10, self.poll_interval_ms + jitter)
            await asyncio.sleep(delay_ms / 1000)

    async def _poll_once(self):
        frames_to_send = []
        async with self.lock:
            # ... (предыдущий код сбора фреймов остается без изменений)
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

        batch = pack_frames(frames_to_send)
        blob = encrypt(self.enc_key, batch)
        
        # Используем скорректированное время
        now = time.time() + self.time_offset
        ts = str(int(now))
        mac = sign(self.hmac_key, self.client_id + ts.encode() + blob)

        params = {"t": ts, "nonce": os.urandom(5).hex()}
        headers = {"X-Cid": b64u_encode(self.client_id), "X-Mac": mac}

        if self.host_header:
            headers["Host"] = self.host_header

        if self.poll_data_in == "header":
            headers["X-Data"] = b64u_encode(blob)

        kwargs = {"params": params, "headers": headers}
        if self.poll_data_in == "body":
            kwargs["content"] = b64u_encode(blob)

        try:
            logger.debug(f"Poll TS={ts} (device time: {time.ctime(now)})")
            resp = await self.http.request(self.poll_method, self.server_url, **kwargs)
            
            # Пытаемся синхронизировать время по заголовку Date от сервера
            if "Date" in resp.headers:
                try:
                    import email.utils
                    server_time = email.utils.parsedate_to_datetime(resp.headers["Date"]).timestamp()
                    new_offset = int(server_time - (now - self.time_offset))
                    if abs(new_offset - self.time_offset) > 2:
                        self.log(f"Time sync: Server time drift is {new_offset}s. Adjusting...")
                        self.time_offset = new_offset
                except: pass

            if resp.status_code == 403:
                self.log("ERROR 403: Forbidden. Check PSK and Time Sync!")
            resp.raise_for_status()
        except Exception as e:
            if "403" in str(e):
                pass # Already logged
            else:
                self.log(f"poll request failed: {e}")
            return

        body = resp.content
        if body:
            try:
                incoming_batch = decrypt(self.enc_key, body)
                incoming_frames = unpack_frames(incoming_batch)
                await self._dispatch_incoming(incoming_frames)
            except Exception as e:
                logger.error(f"decrypt/unpack error: {e}")

    async def _dispatch_incoming(self, frames):
        async with self.lock:
            for f in frames:
                sid = f.session_id.hex()[:8]
                sess = self.sessions.get(f.session_id)
                if not sess:
                    continue
                if (f.flags & FLAG_DATA) and f.payload:
                    try:
                        sess.writer.write(f.payload)
                        await sess.writer.drain()
                    except Exception:
                        pass
                    self._last_activity = time.monotonic()
                if f.flags & FLAG_FIN:
                    try:
                        sess.writer.close()
                    except Exception:
                        pass

    async def stop(self):
        self._stop = True
        await self.http.aclose()

# ── SOCKS5 ────────────────────────────────────────────────────────────

SOCKS_VERSION = 0x05

async def socks5_handshake(reader, writer):
    header = await reader.readexactly(2)
    ver, nmethods = header
    if ver != SOCKS_VERSION:
        raise ConnectionError("bad SOCKS version")
    await reader.readexactly(nmethods)
    writer.write(bytes([SOCKS_VERSION, 0x00]))
    await writer.drain()
    req = await reader.readexactly(4)
    ver, cmd, _rsv, atyp = req
    if cmd != 0x01:
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        raise ConnectionError("only CONNECT supported")
    if atyp == 0x01:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif atyp == 0x03:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode()
    elif atyp == 0x04:
        host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
    else:
        raise ConnectionError("unsupported address type")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()
    return host, port


async def handle_socks_client(tunnel, reader, writer):
    peer = writer.get_extra_info("peername")
    tunnel.log(f"socks: new connection from {peer}")
    try:
        host, port = await socks5_handshake(reader, writer)
    except Exception as e:
        logger.debug(f"socks handshake failed from {peer}: {e}")
        writer.close()
        return
    sid = await tunnel.register_session(writer, host, port)

    async def read_loop():
        try:
            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=30)
                if not data:
                    break
                await tunnel.feed_outgoing(sid, data)
        except asyncio.TimeoutError:
            pass
        except Exception as e:
            tunnel.log(f"socks read error: {e}")
        finally:
            await tunnel.mark_closed(sid)

    asyncio.create_task(read_loop())


async def run_socks5_server(tunnel, bind_host, bind_port):
    server = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w), bind_host, bind_port
    )
    tunnel.log(f"SOCKS5 listening on {bind_host}:{bind_port}")
    async with server:
        await server.serve_forever()

# ── Entry point for Android ───────────────────────────────────────────

_config = None
_loop = None
_tunnel = None
_thread = None
_server = None


def load_config(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


async def run_socks5_server(tunnel, bind_host, bind_port):
    global _server
    _server = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w), bind_host, bind_port
    )
    tunnel.log(f"SOCKS5 listening on {bind_host}:{bind_port}")
    async with _server:
        await _server.serve_forever()


class LogCallbackHandler(logging.Handler):
    def __init__(self, cb):
        super().__init__()
        self.cb = cb
    def emit(self, record):
        try:
            msg = self.format(record)
            self.cb(msg)
        except Exception:
            pass


def _run(config_path: str, log_cb):
    global _loop, _tunnel, _server
    try:
        asyncio.set_event_loop(asyncio.new_event_loop())
        _loop = asyncio.get_event_loop()

        cfg = load_config(config_path)

        # Configure Python logging from config file
        log_level = cfg.get("logging", {}).get("level", "INFO").upper()
        root = logging.getLogger()
        root.setLevel(getattr(logging, log_level, logging.INFO))
        ch = LogCallbackHandler(log_cb)
        ch.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
        root.addHandler(ch)

        logger.info("Log level set to %s", log_level)
        logger.debug("Config loaded: server_url=%s", cfg.get("client", {}).get("server_url"))

        _tunnel = ClientTunnel(cfg)
        _tunnel.set_log_callback(log_cb)

        socks_cfg = cfg["client"]["socks5"]
        poll_task = _loop.create_task(_tunnel.poll_loop())

        log_cb(f"Starting SOCKS5 on {socks_cfg['bind_host']}:{socks_cfg['bind_port']}")
        _loop.run_until_complete(
            run_socks5_server(_tunnel, socks_cfg["bind_host"], socks_cfg["bind_port"])
        )
    except Exception as e:
        if log_cb:
            log_cb(f"CRITICAL ERROR: {e}")
        import traceback
        if log_cb:
            log_cb(traceback.format_exc())
    finally:
        root.handlers = [h for h in root.handlers if not isinstance(h, LogCallbackHandler)]
        if _loop:
            if _server:
                _server.close()
            if _tunnel:
                _loop.run_until_complete(_tunnel.stop())
            _loop.stop()
        _loop = None
        _tunnel = None
        _server = None


def start(config_path: str, log_cb):
    global _thread
    if _thread and _thread.is_alive():
        return
    _thread = threading.Thread(target=_run, args=(config_path, log_cb), daemon=True)
    _thread.start()


def stop():
    global _tunnel, _loop, _server
    if _server:
        _server.close()
    if _tunnel:
        asyncio.run_coroutine_threadsafe(_tunnel.stop(), _loop)



def is_running() -> bool:
    return _thread is not None and _thread.is_alive()
