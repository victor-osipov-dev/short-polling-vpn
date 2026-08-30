"""
Desktop VPN Client — исправленный аналог Android приложения.

Отличия от client.py:
  1. Случайные CDN-образные пути (как в Android proxy_engine.py)
  2. Синхронизация времени по Date-заголовку сервера
  3. .strip() PSK — защита от пробелов/переносов в конфиге
  4. trust_env_proxy из конфига

Запуск:
    python desktop_client.py --config config.yaml

Подключение:
    Настройте v2rayN (или браузер) на SOCKS5-прокси 127.0.0.1:8888
"""

import argparse
import asyncio
import logging
import sys

import yaml

from tunnel import ClientTunnel
from socks5_server import run_socks5_server

logger = logging.getLogger("vpn-client")


# ── HTTP CONNECT прокси-сервер (desktop-only) ──

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
    from socks5_server import enable_tcp_keepalive

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
