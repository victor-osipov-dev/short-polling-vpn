"""
Формат кадров туннеля.

Каждый кадр имеет ЖЁСТКО определённую длину (никаких потоковых/чанкованных
передач) — это соответствует требованию "все запросы и ответы имеют
заранее известную длину".

Frame:
    session_id : 16 байт   - идентификатор логической TCP-сессии
    seq        : 4 байта   - порядковый номер кадра в рамках сессии (для восстановления порядка)
    flags      : 1 байт    - битовые флаги (см. FLAG_*)
    length     : 4 байта   - длина payload в байтах
    payload    : length байт

Несколько кадров пакуются в "батч":
    count : 2 байта
    count x Frame

Батч целиком шифруется (crypto_utils.encrypt) перед отправкой, поэтому
данный модуль работает только с открытым текстом кадров.
"""

import os
import struct

FLAG_NEW = 0x01   # открыть новую сессию: payload = host_len(1) + host + port(2)
FLAG_DATA = 0x02  # обычные данные
FLAG_FIN = 0x04   # закрыть сессию (данные закончились / соединение разорвано)
FLAG_DNS = 0x08   # DNS-запрос/ответ: payload = raw DNS query/response

# Клиент шлёт заголовок X-Proto: 2, чтобы сервер вернул потоковый формат ответа:
#   2 байта magic + последовательность записей [2B длина][AESGCM(кадр)].
# Каждая запись расшифровывается независимо, что позволяет клиенту отдавать
# данные в SOCKS5 по мере поступления, не дожидаясь всего тела ответа.
PROTO_VERSION = "2"
RESP_STREAM_MAGIC = b"\x02\x00"

SESSION_ID_LEN = 16
_HEADER_FMT = "!16sIBI"
_HEADER_LEN = struct.calcsize(_HEADER_FMT)


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
        header = struct.pack(_HEADER_FMT, self.session_id, self.seq & 0xFFFFFFFF,
                              self.flags, len(self.payload))
        return header + self.payload

    @classmethod
    def decode(cls, data: bytes, offset: int = 0):
        if offset + _HEADER_LEN > len(data):
            raise ValueError("truncated frame header")
        session_id, seq, flags, length = struct.unpack_from(_HEADER_FMT, data, offset)
        offset += _HEADER_LEN
        if offset + length > len(data):
            raise ValueError("truncated frame payload")
        payload = data[offset:offset + length]
        offset += length
        return cls(session_id, seq, flags, payload), offset

    @staticmethod
    def new_frame(session_id: bytes, seq: int, host: str, port: int) -> "Frame":
        host_b = host.encode("utf-8")
        if len(host_b) > 255:
            raise ValueError("host too long")
        payload = struct.pack("!B", len(host_b)) + host_b + struct.pack("!H", port)
        return Frame(session_id, seq, FLAG_NEW, payload)

    def parse_new_target(self):
        host_len = self.payload[0]
        host = self.payload[1:1 + host_len].decode("utf-8")
        port = struct.unpack_from("!H", self.payload, 1 + host_len)[0]
        return host, port

    def __repr__(self):
        return f"Frame(sid={self.session_id.hex()[:8]}, seq={self.seq}, flags={self.flags}, len={len(self.payload)})"


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
