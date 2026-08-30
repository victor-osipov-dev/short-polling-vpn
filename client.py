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

import yaml

from tunnel import ClientTunnel
from socks5_server import run_socks5_server

logger = logging.getLogger("vpn-client")


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


def main():
    import argparse
    parser = argparse.ArgumentParser(description="VPN Client (short-polling)")
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

    logger.info("Starting client...")
    logger.info("Server URLs: %s", cfg["client"].get("server_urls", []))

    try:
        asyncio.run(run_client(cfg))
    except KeyboardInterrupt:
        logger.info("Stopped by user")


if __name__ == "__main__":
    main()
