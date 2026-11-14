"""
Общий SOCKS5-сервер для VPN-клиента.

Поддерживает:
  - Аутентификацию: none (метод 0x00)
  - Команды: CONNECT (0x01)
  - Адреса: IPv4 (0x01), домены (0x03), IPv6 (0x04)
  - TCP keepalive
"""

import asyncio
import logging
import socket
import struct
from typing import Tuple, Optional, Callable, Awaitable

logger = logging.getLogger("vpn-socks5")

SOCKS_VERSION = 0x05


def enable_tcp_keepalive(transport) -> None:
    """Включает TCP keepalive на сокете."""
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


async def socks5_handshake(reader: asyncio.StreamReader,
                           writer: asyncio.StreamWriter) -> Tuple[str, Optional[str], Optional[int]]:
    """Выполняет SOCKS5-хэндшейк.

    Возвращает (cmd, host, port):
      - cmd="CONNECT", host=str, port=int — успешный CONNECT
      - cmd="UDP_ASSOCIATE", host=None, port=None — запрос UDP (отклоняется)
    """
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


async def _handle_direct(writer: asyncio.StreamWriter, reader: asyncio.StreamReader,
                         host: str, port: int) -> None:
    """Прямое соединение (split-routing direct) без VPN."""
    try:
        remote_reader, remote_writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=10
        )
    except Exception as exc:
        logger.warning("direct connect %s:%s failed: %s", host, port, exc)
        writer.write(bytes([SOCKS_VERSION, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        writer.close()
        return
    writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()
    enable_tcp_keepalive(remote_writer.transport)

    async def pump(src, dst):
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass

    await asyncio.gather(pump(reader, remote_writer), pump(remote_reader, writer))


async def handle_socks_client(
    tunnel,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    on_connect: Optional[Callable] = None,
):
    """Обрабатывает одно SOCKS5-соединение.

    tunnel — объект с методами register_session(), feed_outgoing(), mark_closed().
    on_connect — опциональный callback после успешного handshake.
    """
    peer = writer.get_extra_info("peername")
    try:
        cmd, host, port = await socks5_handshake(reader, writer)
    except Exception as e:
        logger.error("socks handshake failed from %s: %s", peer, e)
        writer.close()
        return

    if cmd == "UDP_ASSOCIATE":
        writer.write(bytes([SOCKS_VERSION, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
        await writer.drain()
        writer.close()
        return

    route = ("tunnel", None, None)
    if hasattr(tunnel, "route_for"):
        try:
            route = tunnel.route_for(host)
        except Exception as exc:
            logger.warning("route_for(%s) failed: %s", host, exc)

    if route[0] == "direct":
        await _handle_direct(writer, reader, host, port)
        return

    writer.write(bytes([SOCKS_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
    await writer.drain()

    sid = await tunnel.register_session(writer, host, port, server_base=route[1],
                                        route=route[2] if len(route) > 2 else ())
    enable_tcp_keepalive(writer.transport)

    if on_connect:
        on_connect(sid, host, port)

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


async def run_socks5_server(tunnel, bind_host: str, bind_port: int):
    """Запускает SOCKS5-сервер."""
    server = await asyncio.start_server(
        lambda r, w: handle_socks_client(tunnel, r, w),
        bind_host, bind_port,
        reuse_address=True
    )
    addrs = ", ".join(str(s.getsockname()) for s in server.sockets)
    logger.info("SOCKS5 listening on %s", addrs)
    async with server:
        await server.serve_forever()
