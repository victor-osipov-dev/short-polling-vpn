"""
Точка входа. Запуск:

    python main.py --config config.yaml

Режим (client/server) определяется полем `mode` в config.yaml,
либо может быть переопределён флагом --mode.
"""

import argparse
import asyncio
import logging
import sys

import yaml


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def setup_logging(cfg: dict):
    level_name = cfg.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # aiohttp логирует каждый poll-запрос в INFO. При 5-20 запросах/с это
    # забивает журнал сервера — оставляем только ошибки доступа.
    logging.getLogger("aiohttp.access").setLevel(logging.WARNING)


def main():
    parser = argparse.ArgumentParser(description="vpn-poller: HTTP short-polling VPN protocol")
    parser.add_argument("--config", default="config.yaml", help="путь к config.yaml")
    parser.add_argument("--mode", choices=["client", "server"], help="переопределить mode из конфига")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.mode:
        cfg["mode"] = args.mode

    setup_logging(cfg)

    mode = cfg.get("mode")
    if mode == "client":
        import client
        asyncio.run(client.run_client(cfg))
    elif mode == "server":
        import server
        server.run_server(cfg)
    else:
        print(f"Unknown mode: {mode!r}. Use 'client' or 'server' in config.yaml.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
