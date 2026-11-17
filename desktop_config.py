"""Профили и конфигурация desktop-клиента.

Аналог Android `ConfigManager.kt`: хранит именованные профили в
`profiles.json`, умеет импортировать подписки, применять `client_profiles`
и собирать конфиг для общего движка `tunnel.ClientTunnel`.

Модель профиля повторяет Android `ProxyConfig`, поэтому подписки и
настройки переносимы между Android и ПК.
"""

from __future__ import annotations

import copy
import hashlib
import json
import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

logger = logging.getLogger("vpn-desktop-config")

PROFILES_FILE = "profiles.json"
PREFS_FILE = "desktop_prefs.json"

# Значения по умолчанию для desktop-профиля. Отличаются от Android
# только портами/интервалами, чтобы не зависеть от мобильных особенностей.
DEFAULT_PSK = "REPLACE_WITH_GENERATED_PSK"


def default_client_config() -> dict:
    return {
        # http_port живёт внутри socks5, как ожидает desktop_client.run_client.
        "socks5": {"bind_host": "127.0.0.1", "bind_port": 8888, "http_port": 8889},
        "server_url": "",
        "server_urls": [],
        "server_selector": "round",
        "poll_path": "/poll",
        "poll_interval_ms": 200,
        "poll_jitter_ms": 50,
        "pad_polls": True,
        "max_chunk_bytes": 65536,
        "verify_tls": True,
        "poll_method": "POST",
        "poll_data_in": "body",
        "host_header": "",
        "trust_env_proxy": False,
        "url_fail_limit": 3,
        "url_cooldown_seconds": 60,
        "disabled_urls": [],
        "idle_timeout": {"enabled": False, "seconds": 300},
        "dns_relay": {"enabled": False, "bind_host": "127.0.0.1", "bind_port": 5353},
        # Привязка poll-запросов к IP физического адаптера (TUN-режим).
        "local_address": "",
        # Настоящий VPN через Wintun (tun2proxy). Используется, когда
        # профиль в режиме "vpn" и backend == "tun".
        "tun": {
            "mtu": 1500,
            # Имя Wintun-адаптера: удобно искать в ipconfig и удалять после
            # аварийного завершения.
            "name": "vpnclient",
            # virtual: tun2proxy сам отвечает на DNS и передаёт имена дальше —
            # наш SOCKS5 умеет только TCP CONNECT, поэтому UDP DNS не годится.
            "dns_mode": "virtual",
            "bypass_ips": [],
            "helper_port": 41417,
            "verbosity": "info",
            # DNS физического адаптера переключается на шлюз TUN, иначе
            # Windows продолжает спрашивать DNS провайдера параллельно.
            "dns_hijack": True,
        },
    }


def default_profile_config() -> dict:
    return {
        "subscription": {"url": "", "file": "", "name": ""},
        "user": {"uuid": "", "secret": "", "device_id": ""},
        "routing": {"enabled": False, "ru": "", "non_ru": "", "private": "direct"},
        "routing_options": "",
        "nodes": [],
        "routes": [],
        "client": default_client_config(),
        "security": {"psk": DEFAULT_PSK, "hmac_window_seconds": 30},
        "logging": {"level": "INFO"},
    }


def normalize_subscription_url(url: str) -> str:
    return (url or "").strip().rstrip("/")


def subscription_slug(url: str, user_uuid: str) -> str:
    """Стабильный короткий id подписки (совместим с Android: UUID v3 от MD5)."""
    if url.strip():
        key = "url:" + normalize_subscription_url(url)
    elif user_uuid.strip():
        key = "user:" + user_uuid.strip()
    else:
        key = "subscription"
    digest = hashlib.md5(key.encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest, version=3))[:8]


def _deep_merge(base: dict, override: dict) -> dict:
    """Рекурсивно перекрывает base значениями override (base не мутируется)."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class DesktopConfig:
    """Хранилище профилей и настроек desktop-клиента.

    Доступ к файлам сериализован блокировкой: импорт подписки идёт в фоновом
    потоке, а UI читает профили из главного — без этого `os.replace` на
    Windows падает с «access denied», пока файл открыт на чтение.
    """

    def __init__(self, base_dir: str | os.PathLike = "."):
        self.base_dir = Path(base_dir).resolve()
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.profiles_path = self.base_dir / PROFILES_FILE
        self.prefs_path = self.base_dir / PREFS_FILE
        self._lock = threading.RLock()
        self._prefs: dict = self._read_json(self.prefs_path, {})

    # ── Низкоуровневый JSON ───────────────────────────────────────────

    @staticmethod
    def _read_json(path: Path, fallback):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return fallback

    def _write_json(self, path: Path, data) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        with self._lock:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            last_exc = None
            for attempt in range(5):
                try:
                    os.replace(tmp, path)
                    return
                except PermissionError as exc:  # файл занят (антивирус/индексатор)
                    last_exc = exc
                    time.sleep(0.05 * (attempt + 1))
            try:
                os.remove(tmp)
            except Exception:
                pass
            if last_exc:
                raise last_exc

    # ── Настройки приложения (язык, активный профиль) ─────────────────

    def _save_prefs(self) -> None:
        self._write_json(self.prefs_path, self._prefs)

    def get_pref(self, key: str, default=None):
        with self._lock:
            return self._prefs.get(key, default)

    def set_pref(self, key: str, value) -> None:
        with self._lock:
            self._prefs[key] = value
            self._save_prefs()

    # ── Профили ───────────────────────────────────────────────────────

    def _normalize_profile(self, raw: dict) -> dict:
        profile = {
            "id": str(raw.get("id") or uuid.uuid4()),
            "name": str(raw.get("name") or "Profile"),
            "mode": "vpn" if str(raw.get("mode", "proxy")) == "vpn" else "proxy",
            # Как реализуется режим "vpn": "tun" (Wintun, весь трафик) или
            # "system" (системный прокси Windows). "proxy" игнорирует поле.
            "vpn_backend": "system" if str(raw.get("vpn_backend", "tun")) == "system" else "tun",
            "config": _deep_merge(default_profile_config(), raw.get("config") or {}),
        }
        return profile

    def load_profiles(self) -> list[dict]:
        raw = self._read_json(self.profiles_path, None)
        if not raw or not isinstance(raw, dict):
            return []
        profiles = raw.get("profiles") or []
        return [self._normalize_profile(p) for p in profiles if isinstance(p, dict)]

    def save_profiles(self, profiles: list[dict]) -> None:
        active = self._prefs.get("active_profile") or (profiles[0]["id"] if profiles else "")
        self._write_json(self.profiles_path, {
            "active": active,
            "profiles": profiles,
        })
    def ensure_profiles(self) -> list[dict]:
        if not self.profiles_path.exists():
            self.save_profiles([])
        return self.load_profiles()

    def get_active_id(self) -> str:
        return str(self._prefs.get("active_profile") or "")

    def get_active_profile(self) -> Optional[dict]:
        profiles = self.load_profiles()
        if not profiles:
            return None
        active_id = self.get_active_id()
        for p in profiles:
            if p["id"] == active_id:
                return p
        return profiles[0]

    def select_profile(self, profile_id: str) -> None:
        self.set_pref("active_profile", profile_id)

    def add_profile(self, profile: dict) -> None:
        profiles = self.load_profiles()
        profiles.append(self._normalize_profile(profile))
        self.save_profiles(profiles)

    def update_profile(self, profile: dict) -> None:
        profiles = self.load_profiles()
        profile = self._normalize_profile(profile)
        for i, p in enumerate(profiles):
            if p["id"] == profile["id"]:
                profiles[i] = profile
                break
        else:
            profiles.append(profile)
        self.save_profiles(profiles)

    def delete_profile(self, profile_id: str) -> None:
        profiles = self.load_profiles()
        remaining = [p for p in profiles if p["id"] != profile_id]
        if self.get_active_id() == profile_id:
            self.set_pref("active_profile", remaining[0]["id"] if remaining else "")
        self.save_profiles(remaining)

    # ── Подписки ──────────────────────────────────────────────────────

    def profiles_of_subscription(self, url: str) -> list[dict]:
        key = normalize_subscription_url(url)
        if not key:
            return []
        return [p for p in self.load_profiles()
                if normalize_subscription_url(p["config"].get("subscription", {}).get("url", "")) == key]

    def group_profiles(self) -> list[tuple[str, list[dict]]]:
        """Профили, сгруппированные по URL подписки (пустой ключ = локальные)."""
        order: list[str] = []
        groups: dict[str, list[dict]] = {}
        for p in self.load_profiles():
            key = normalize_subscription_url(p["config"].get("subscription", {}).get("url", ""))
            if key not in groups:
                groups[key] = []
                order.append(key)
            groups[key].append(p)
        return [(key, groups[key]) for key in order]

    def delete_subscription(self, url: str) -> None:
        key = normalize_subscription_url(url)
        if not key:
            return
        profiles = self.load_profiles()
        remaining = [
            p for p in profiles
            if normalize_subscription_url(p["config"].get("subscription", {}).get("url", "")) != key
        ]
        if self.get_active_id() and all(p["id"] != self.get_active_id() for p in remaining):
            self.set_pref("active_profile", remaining[0]["id"] if remaining else "")
        self.save_profiles(remaining)

    def _prune_subscription(self, url: str, keep_ids: set[str]) -> None:
        key = normalize_subscription_url(url)
        if not key:
            return
        profiles = self.load_profiles()
        remaining = [
            p for p in profiles
            if not (normalize_subscription_url(p["config"].get("subscription", {}).get("url", "")) == key
                    and p["id"] not in keep_ids)
        ]
        if self.get_active_id() and all(p["id"] != self.get_active_id() for p in remaining):
            self.set_pref("active_profile", remaining[0]["id"] if remaining else "")
        self.save_profiles(remaining)

    def import_subscription(self, sub: dict, source_url: str = "", select: bool = True) -> Optional[dict]:
        """Импорт подписки: обновляет только её профили, другие не трогает.

        Под блокировкой, чтобы фоновый импорт и UI-правки не теряли друг
        друга (read-modify-write над profiles.json).
        """
        with self._lock:
            return self._import_subscription_locked(sub, source_url, select)

    def _import_subscription_locked(self, sub: dict, source_url: str = "",
                                    select: bool = True) -> Optional[dict]:
        user = sub.get("user") or {}
        user_uuid = str(user.get("uuid") or "")
        secret = str(user.get("secret") or "")
        user_name = str(user.get("name") or "")
        sub_block = sub.get("subscription") or {}
        url = (source_url or "").strip() or str(sub_block.get("url") or "")

        nodes = sub.get("nodes") or []
        node_urls = [str(n.get("url")).rstrip("/") for n in nodes if n.get("url")]
        profiles_arr = sub.get("profiles") or []
        client_profiles_arr = sub.get("client_profiles") or []
        routes_arr = sub.get("routes") or []

        canonical_routes: list[dict] = []
        seen_routes: set[str] = set()

        def add_route(route: Optional[dict]) -> None:
            if not isinstance(route, dict):
                return
            name = str(route.get("name") or "")
            if not name or name in seen_routes:
                return
            seen_routes.add(name)
            canonical_routes.append({"name": name, "hops": route.get("hops") or []})

        for route in routes_arr:
            add_route(route)
        for prof in profiles_arr:
            for route in (prof or {}).get("routes") or []:
                add_route(route)
        route_names = list(seen_routes)

        split = sub.get("split_routing") or {}
        actions = split.get("actions") or {}

        def action(name: str) -> str:
            a = actions.get(name) or {}
            if a.get("direct"):
                return "direct"
            return str(a.get("route") or "")

        display = user_name or url.replace("https://", "").replace("http://", "").split("/")[0] or "Subscription"
        normalized_url = normalize_subscription_url(url)
        all_profiles = self.load_profiles()
        existing = next(
            (p for p in all_profiles
             if normalized_url
             and normalize_subscription_url(p["config"].get("subscription", {}).get("url", "")) == normalized_url),
            None,
        )
        if existing is None and not normalized_url and user_uuid:
            existing = next((p for p in all_profiles if p["config"]["user"].get("uuid") == user_uuid), None)

        base = copy.deepcopy(existing["config"]) if existing else copy.deepcopy(
            (self.get_active_profile() or {}).get("config") or default_profile_config())
        device_id = (existing["config"]["user"].get("device_id") if existing else "") or str(uuid.uuid4())
        slug = subscription_slug(url, user_uuid)

        defs = []
        for cp in client_profiles_arr:
            if not isinstance(cp, dict) or not cp.get("enabled", True):
                continue
            defs.append(cp)

        if defs:
            imported: list[dict] = []
            keep_ids: set[str] = set()
            for cp in defs:
                cp_id = str(cp.get("id") or uuid.uuid4())
                local_id = f"sub:{slug}:{cp_id}"
                existing_profile = next((p for p in all_profiles if p["id"] == local_id), None)
                if existing_profile is None and normalized_url:
                    existing_profile = next(
                        (p for p in all_profiles
                         if normalize_subscription_url(p["config"].get("subscription", {}).get("url", ""))
                         == normalized_url and p["name"] == cp.get("name")),
                        None,
                    )
                prev_config = existing_profile["config"] if existing_profile else base
                updated = copy.deepcopy(base)
                updated["subscription"] = {"url": normalized_url, "file": "", "name": display}
                updated["user"] = {
                    "uuid": user_uuid or prev_config["user"].get("uuid", ""),
                    "secret": secret or prev_config["user"].get("secret", ""),
                    "device_id": device_id,
                }
                updated["client"]["server_url"] = node_urls[0] if node_urls else prev_config["client"].get("server_url", "")
                updated["client"]["server_urls"] = node_urls or prev_config["client"].get("server_urls", [])
                updated["nodes"] = nodes
                updated["routes"] = canonical_routes
                updated["routing"] = {
                    "enabled": bool(cp.get("split_enabled")),
                    "ru": cp.get("route_ru") or prev_config["routing"].get("ru", ""),
                    "non_ru": cp.get("route_non_ru") or prev_config["routing"].get("non_ru", ""),
                    "private": cp.get("route_private") or prev_config["routing"].get("private", "direct"),
                }
                updated["routing_options"] = "|".join(route_names) if route_names else prev_config.get("routing_options", "")
                profile = {
                    "id": existing_profile["id"] if existing_profile else local_id,
                    "name": str(cp.get("name") or "Profile"),
                    # Пользовательский выбор режима не перетираем обновлением
                    # подписки: иначе Proxy/system-proxy молча возвращаются в TUN.
                    "mode": existing_profile["mode"] if existing_profile else
                            ("vpn" if str(cp.get("mode", "proxy")) == "vpn" else "proxy"),
                    "vpn_backend": (existing_profile or {}).get("vpn_backend", "tun"),
                    "config": updated,
                }
                self.update_profile(profile)
                imported.append(profile)
                keep_ids.add(profile["id"])
            self._prune_subscription(normalized_url, keep_ids)
            if select and imported:
                self.select_profile(imported[0]["id"])
            return imported[0]

        # Подписка без client_profiles: один профиль на всю подписку.
        updated = copy.deepcopy(base)
        updated["subscription"] = {"url": normalized_url, "file": "", "name": display}
        updated["user"] = {
            "uuid": user_uuid or base["user"].get("uuid", ""),
            "secret": secret or base["user"].get("secret", ""),
            "device_id": device_id,
        }
        updated["client"]["server_url"] = node_urls[0] if node_urls else base["client"].get("server_url", "")
        updated["client"]["server_urls"] = node_urls or base["client"].get("server_urls", [])
        updated["nodes"] = nodes
        updated["routes"] = canonical_routes
        if existing:
            updated["routing"] = {
                "enabled": bool(split.get("enabled", False)) or base["routing"].get("enabled", False),
                "ru": base["routing"].get("ru", "") or action("ru"),
                "non_ru": base["routing"].get("non_ru", "") or action("non_ru"),
                "private": base["routing"].get("private", "") or action("private") or "direct",
            }
        else:
            updated["routing"] = {
                "enabled": bool(split.get("enabled", False)),
                "ru": action("ru"),
                "non_ru": action("non_ru"),
                "private": action("private") or "direct",
            }
        updated["routing_options"] = "|".join(route_names) if route_names else base.get("routing_options", "")

        profile = {
            "id": existing["id"] if existing else f"sub:{slug}:default",
            "name": display,
            # Сохраняем выбранный пользователем режим при обновлении подписки.
            "mode": existing["mode"] if existing else
                    ("vpn" if str((sub.get("user") or {}).get("mode", "proxy")) == "vpn" else "proxy"),
            "vpn_backend": (existing or {}).get("vpn_backend", "tun"),
            "config": updated,
        }
        self.update_profile(profile)
        self._prune_subscription(normalized_url, {profile["id"]})
        if select:
            self.select_profile(profile["id"])
        return profile

    # ── Сборка конфига для движка ─────────────────────────────────────

    def engine_config(self, profile: Optional[dict] = None) -> dict:
        """Собирает dict, который понимает tunnel.ClientTunnel."""
        profile = profile or self.get_active_profile()
        if profile is None:
            profile = self._normalize_profile({"name": "Default"})
        cfg = profile["config"]
        out: dict = {"mode": "client"}

        sub = cfg.get("subscription") or {}
        if sub.get("url") or sub.get("file") or sub.get("name"):
            out["subscription"] = {
                "url": sub.get("url", ""),
                "file": sub.get("file", ""),
                "name": sub.get("name", ""),
            }
        user = cfg.get("user") or {}
        if user.get("uuid") or user.get("secret") or user.get("device_id"):
            out["user"] = {
                "uuid": user.get("uuid", ""),
                "secret": user.get("secret", ""),
                "device_id": user.get("device_id", ""),
            }
        routing = cfg.get("routing") or {}
        out["routing"] = {
            "enabled": bool(routing.get("enabled", False)),
            "ru": routing.get("ru", ""),
            "non_ru": routing.get("non_ru", ""),
            "private": routing.get("private", "direct"),
        }
        if cfg.get("routing_options"):
            out["routing_options"] = cfg["routing_options"]
        if cfg.get("nodes"):
            out["nodes"] = copy.deepcopy(cfg["nodes"])
        if cfg.get("routes"):
            out["routes"] = copy.deepcopy(cfg["routes"])
        out["client"] = copy.deepcopy(cfg.get("client") or default_client_config())
        out["security"] = copy.deepcopy(cfg.get("security") or {"psk": DEFAULT_PSK})
        out["logging"] = copy.deepcopy(cfg.get("logging") or {"level": "INFO"})
        return out

    # ── Миграция из config.yaml ───────────────────────────────────────

    def seed_from_yaml(self, yaml_path: str | os.PathLike) -> Optional[dict]:
        """Если профилей нет — создаёт один из существующего config.yaml."""
        path = Path(yaml_path)
        if self.profiles_path.exists() or not path.exists():
            return None
        try:
            import yaml
            with open(path, "r", encoding="utf-8") as f:
                old = yaml.safe_load(f) or {}
        except Exception as exc:
            logger.warning("seed_from_yaml: %s", exc)
            return None

        client = _deep_merge(default_client_config(), old.get("client") or {})
        config = default_profile_config()
        config["client"] = client
        config["security"] = _deep_merge(config["security"], old.get("security") or {})
        config["logging"] = _deep_merge(config["logging"], old.get("logging") or {})
        if old.get("user"):
            config["user"] = _deep_merge(config["user"], old["user"])
        if old.get("subscription"):
            config["subscription"] = _deep_merge(config["subscription"], old["subscription"])
        if old.get("nodes"):
            config["nodes"] = old["nodes"]
        if old.get("routes"):
            config["routes"] = old["routes"]
        if old.get("routing"):
            config["routing"] = _deep_merge(config["routing"], old["routing"])

        profile = self._normalize_profile({"name": "Default", "mode": "proxy", "config": config})
        self.save_profiles([profile])
        self.set_pref("active_profile", profile["id"])
        logger.info("seeded desktop profile from %s", path)
        return profile
