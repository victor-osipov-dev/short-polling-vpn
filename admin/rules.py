"""Обновление публичных списков RU GeoIP / доменов.

    python -m admin.rules --config admin/config.yaml --update
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.request

import yaml


def fetch(url: str, timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "vpn-rules/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def write_atomic(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def main() -> None:
    parser = argparse.ArgumentParser(description="VPN rules updater")
    parser.add_argument("--config", default="admin/config.yaml")
    parser.add_argument("--update", action="store_true", help="скачать списки")
    args = parser.parse_args()
    if not args.update:
        parser.print_help()
        return

    with open(args.config, "r", encoding="utf-8") as f:
        cfg = yaml.safe_load(f) or {}

    rules_dir = cfg.get("rules_dir") or "admin/data/rules"
    sources = cfg.get("rules_sources") or {}
    targets = {
        "geoip": os.path.join(rules_dir, "geoip-ru.txt"),
        "domains": os.path.join(rules_dir, "ru-domains.txt"),
    }
    for key, target in targets.items():
        url = sources.get(key)
        if not url:
            print(f"{key}: no source configured, skip", file=sys.stderr)
            continue
        try:
            data = fetch(url)
            write_atomic(target, data)
            lines = data.count(b"\n") + 1
            print(f"{key}: {lines} lines -> {target}")
        except Exception as exc:
            print(f"{key}: update failed: {exc}", file=sys.stderr)


if __name__ == "__main__":
    main()
