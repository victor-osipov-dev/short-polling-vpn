"""Аутентификация пользователей для VPN-сервера.

Читает пользователей из SQLite (ту же БД, что и admin-панель) и
расшифровывает секреты cluster-ключом. Кэширует отметки устройств,
чтобы не писать last_seen на каждый poll.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

try:
    from .store import Store
except ImportError:  # запуск из корня проекта
    from admin.store import Store

logger = logging.getLogger("vpn-user-auth")


class UserAuth:
    def __init__(self, db_path: str, cluster_key_path: str):
        self.store = Store(db_path, cluster_key_path, node_id="vpn-server")
        self._seen: dict[tuple[str, str], float] = {}

    def authenticate(self, user_uuid: str, device_id: str) -> Optional[bytes]:
        if not user_uuid or not device_id:
            return None
        user = self.store.get_user(user_uuid)
        if user is None or not user.enabled:
            return None
        if user.expires_at and user.expires_at < int(time.time() * 1000):
            return None
        return self.store.get_secret(user_uuid)

    def touch_device(self, user_uuid: str, device_id: str, ip: str = "",
                     name: str = "") -> tuple[bool, str]:
        """Регистрирует устройство не чаще раза в минуту."""
        key = (user_uuid, device_id)
        now = time.monotonic()
        if now - self._seen.get(key, 0.0) < 60:
            return True, "ok"
        try:
            ok, reason = self.store.register_device(user_uuid, device_id, name, ip)
        except Exception as exc:
            # SQLite может быть занят admin-панелью/репликацией. Пользователь
            # уже прошёл authenticate() перед этим вызовом, поэтому рабочий
            # туннель рвать нельзя: считаем устройство известным до минуты.
            logger.warning("touch_device(%s/%s) failed: %s", user_uuid, device_id, exc)
            self._seen[key] = now
            return True, "ok"
        if ok:
            self._seen[key] = now
        return ok, reason

    def close(self) -> None:
        self.store.close()
