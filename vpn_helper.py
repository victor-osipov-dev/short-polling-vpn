"""Точка входа elevated-помощника TUN-режима.

Запускается с правами администратора (UAC) один раз на сессию приложения:

    vpn_helper.py --port 41417 --token <random>

Слушает 127.0.0.1, принимает JSON-Lines команды start/stop/ping/quit и
управляет процессом tun2proxy-bin.exe (который и создаёт Wintun-адаптер).
Помощник держит консоль скрытой; при сборке PyInstaller используется
отдельный exe с тем же флагом (--tun-helper).
"""

from __future__ import annotations

import argparse
import logging
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description="TUN helper (elevated)")
    parser.add_argument("--port", type=int, default=41417)
    parser.add_argument("--token", default="")
    parser.add_argument("--idle-timeout", type=float, default=0.0,
                        help="выйти после N секунд без клиентов (0 = не выходить)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] vpn-helper: %(message)s",
        stream=sys.stderr,
    )

    from tun_mode import run_helper_server

    run_helper_server(args.port, args.token, idle_timeout=args.idle_timeout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
