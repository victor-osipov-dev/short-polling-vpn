"""Загрузка и применение подписки.

Подписка — JSON, который отдаёт admin-панель:
  GET https://SERVER:8443/sub/<token>

Также можно указать локальный файл.
"""

from __future__ import annotations

import json
import os
import uuid
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def load_subscription(source: str, timeout: int = 10) -> dict:
    if not source:
        raise ValueError("empty subscription source")
    parsed = urlparse(source)
    if parsed.scheme in ("http", "https"):
        req = Request(source, headers={"User-Agent": "vpn-client/1.0"})
        with urlopen(req, timeout=timeout) as resp:
            data = resp.read()
    else:
        with open(source, "r", encoding="utf-8") as f:
            data = f.read()
    sub = json.loads(data)
    if not isinstance(sub, dict):
        raise ValueError("subscription must be a JSON object")
    return sub


def apply_subscription(cfg: dict, sub: dict) -> dict:
    """Локально применяет подписку к конфигу клиента.

    Секрет/узлы/профили/правила приходят с сервера; device_id сохраняется
    локальный, чтобы устройство не менялось при обновлении подписки.
    """
    user = dict(sub.get("user") or {})
    existing_user = cfg.get("user") or {}
    if not user.get("device_id"):
        user["device_id"] = existing_user.get("device_id") or str(uuid.uuid4())
    if user.get("uuid") and user.get("secret"):
        cfg["user"] = user

    nodes = sub.get("nodes") or []
    urls = [str(n.get("url")).rstrip("/") for n in nodes if n.get("url")]
    if urls:
        client = cfg.setdefault("client", {})
        client["server_urls"] = urls
        client["server_url"] = urls[0]
    cfg["nodes"] = nodes
    # Новый формат: отдельный каталог маршрутов (может быть любой длины).
    # Он приоритетнее старого profiles[].routes.
    if sub.get("routes"):
        cfg["routes"] = sub["routes"]
    if sub.get("profiles"):
        cfg["profiles"] = sub["profiles"]
    if sub.get("split_routing"):
        cfg["split_routing"] = sub["split_routing"]
    if sub.get("subscription"):
        cfg["subscription"] = sub["subscription"]

    # Локальные переопределения маршрутов из UI (routing):
    # enabled, ru, non_ru, private -> "direct" или имя маршрута.
    routing = cfg.get("routing") or {}
    if routing:
        split = cfg.setdefault("split_routing", {})
        if "enabled" in routing:
            split["enabled"] = bool(routing["enabled"])
        actions = dict(split.get("actions") or {})
        for category in ("ru", "non_ru", "private"):
            value = routing.get(category)
            if not value:
                continue
            if str(value).lower() == "direct":
                actions[category] = {"direct": True}
            else:
                actions[category] = {"route": str(value)}
        split["actions"] = actions
    return cfg


def load_and_apply(cfg: dict) -> dict:
    sub_cfg = cfg.get("subscription") or {}
    source = sub_cfg.get("url") or sub_cfg.get("file") or ""
    if not source:
        return cfg
    try:
        sub = load_subscription(source)
        apply_subscription(cfg, sub)
    except Exception as exc:
        # Подписка недоступна — работаем на локальных настройках.
        import logging
        logging.getLogger("vpn-subscription").warning("subscription load failed: %s", exc)
    return cfg
