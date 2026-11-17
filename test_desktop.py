"""Тесты desktop-конфигурации (профили, подписки, сборка конфига движка).

Не требуют сети: подписка берётся из встроенного образца.
"""

import base64
import os
import tempfile
import time
import unittest

from desktop_config import (
    DesktopConfig,
    default_profile_config,
    normalize_subscription_url,
    subscription_slug,
)
from tunnel import ClientTunnel

SAMPLE_SUB = {
    "version": 1,
    "user": {"uuid": "11111111-2222-3333-4444-555555555555", "name": "test-user",
             "secret": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
    "subscription": {"url": "https://fimdi.ru/sub/token", "auto_update_hours": 6},
    "nodes": [
        {"id": "ru-2", "name": "RU exit", "url": "https://fimdi.ru", "region": "RU"},
        {"id": "ru-2-direct", "name": "RU direct", "url": "https://data.fimdi.ru:8443", "region": "RU"},
        {"id": "fi-1", "name": "FI exit", "url": "https://177.3.220.12:8443", "region": "FI"},
        {"id": "de-1", "name": "DE exit", "url": "https://2.27.37.211:8443", "region": "DE"},
    ],
    "routes": [
        {"id": "r1", "name": "DE exit", "hops": [{"candidates": ["de-1"], "strategy": "round"}]},
        {"id": "r2", "name": "RU exit", "hops": [{"candidates": ["ru-2"], "strategy": "round"}]},
        {"id": "r3", "name": "RU -> DE",
         "hops": [{"candidates": ["ru-2"]}, {"candidates": ["de-1"]}]},
    ],
    "client_profiles": [
        {"id": "cp-de", "name": "Германия", "mode": "vpn", "enabled": True,
         "split_enabled": True, "route_ru": "", "route_non_ru": "DE exit",
         "route_private": "direct", "sort_order": 0},
        {"id": "cp-ru", "name": "Россия", "mode": "vpn", "enabled": True,
         "split_enabled": True, "route_ru": "RU exit", "route_non_ru": "RU -> DE",
         "route_private": "direct", "sort_order": 1},
        {"id": "cp-off", "name": "Отключённый", "mode": "vpn", "enabled": False,
         "split_enabled": True, "route_ru": "", "route_non_ru": "DE exit",
         "route_private": "direct", "sort_order": 2},
    ],
    "split_routing": {
        "enabled": True, "default": "non_ru",
        "rules": {"geoip": "https://fimdi.ru/rules/geoip-ru.txt"},
        "actions": {"ru": {"route": "RU exit"}, "non_ru": {"route": "DE exit"},
                    "private": {"direct": True}},
    },
}


class DesktopConfigTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpn-desktop-test-")
        self.store = DesktopConfig(self.tmp)

    def test_slug_matches_android_uuid_v3(self):
        # Android: UUID.nameUUIDFromBytes(key.toByteArray()).toString().take(8)
        slug = subscription_slug("https://fimdi.ru/sub/token", "")
        self.assertEqual(len(slug), 8)
        self.assertEqual(slug, subscription_slug("https://fimdi.ru/sub/token/", ""))
        self.assertNotEqual(slug, subscription_slug("https://other/sub", ""))

    def test_normalize_url(self):
        self.assertEqual(normalize_subscription_url(" https://a/b/ "), "https://a/b")

    def test_import_creates_enabled_profiles_only(self):
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        profiles = self.store.load_profiles()
        names = [p["name"] for p in profiles]
        self.assertEqual(names, ["Германия", "Россия"])
        self.assertNotIn("Отключённый", names)

    def test_import_is_idempotent(self):
        first = self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        ids = {p["id"] for p in self.store.load_profiles()}
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token", select=False)
        self.assertEqual({p["id"] for p in self.store.load_profiles()}, ids)
        self.assertEqual(len(self.store.load_profiles()), 2)
        self.assertEqual(first["id"], self.store.load_profiles()[0]["id"])

    def test_import_keeps_device_id(self):
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        device = self.store.load_profiles()[0]["config"]["user"]["device_id"]
        self.assertTrue(device)
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token", select=False)
        self.assertEqual(self.store.load_profiles()[0]["config"]["user"]["device_id"], device)

    def test_import_keeps_user_chosen_mode(self):
        # Обновление подписки не должно возвращать Proxy/system в TUN.
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        germany = next(p for p in self.store.load_profiles() if p["name"] == "Германия")
        germany["mode"] = "proxy"
        germany["vpn_backend"] = "system"
        self.store.update_profile(germany)

        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token", select=False)
        again = next(p for p in self.store.load_profiles() if p["name"] == "Германия")
        self.assertEqual(again["mode"], "proxy")
        self.assertEqual(again["vpn_backend"], "system")

    def test_engine_config_maps_routing(self):
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        germany = next(p for p in self.store.load_profiles() if p["name"] == "Германия")
        engine = self.store.engine_config(germany)
        self.assertEqual(engine["mode"], "client")
        self.assertEqual(engine["routing"]["enabled"], True)
        self.assertEqual(engine["routing"]["non_ru"], "DE exit")
        self.assertEqual(engine["routing"]["private"], "direct")
        self.assertEqual(len(engine["nodes"]), 4)
        self.assertEqual(len(engine["routes"]), 3)
        self.assertEqual(engine["user"]["uuid"], SAMPLE_SUB["user"]["uuid"])
        self.assertEqual(engine["client"]["server_urls"][0], "https://fimdi.ru")

    def test_second_subscription_isolated(self):
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        self.store.import_subscription(SAMPLE_SUB, "https://other/sub/token")
        self.assertEqual(len(self.store.load_profiles()), 4)
        self.store.delete_subscription("https://fimdi.ru/sub/token")
        remaining = self.store.load_profiles()
        self.assertEqual(len(remaining), 2)
        for p in remaining:
            self.assertEqual(
                normalize_subscription_url(p["config"]["subscription"]["url"]),
                "https://other/sub/token")

    def test_group_profiles(self):
        self.store.import_subscription(SAMPLE_SUB, "https://fimdi.ru/sub/token")
        groups = self.store.group_profiles()
        self.assertEqual(len(groups), 1)
        self.assertEqual(len(groups[0][1]), 2)

    def test_seed_from_yaml(self):
        yaml_path = os.path.join(self.tmp, "config.yaml")
        with open(yaml_path, "w", encoding="utf-8") as f:
            f.write(
                "mode: client\n"
                "client:\n"
                "  server_url: https://example:8443\n"
                "  poll_interval_ms: 150\n"
                "security:\n"
                "  psk: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"
            )
        profile = self.store.seed_from_yaml(yaml_path)
        self.assertIsNotNone(profile)
        engine = self.store.engine_config(profile)
        self.assertEqual(engine["client"]["server_url"], "https://example:8443")
        self.assertEqual(engine["client"]["poll_interval_ms"], 150)
        # Повторный вызов ничего не делает.
        self.assertIsNone(self.store.seed_from_yaml(yaml_path))

    def test_default_profile_config_has_http_port(self):
        cfg = default_profile_config()
        self.assertIn("http_port", cfg["client"]["socks5"])


class ClientTunnelKeysTest(unittest.TestCase):
    """Ключи туннеля: per-user секрет из подписки важнее общего PSK."""

    def _base_cfg(self):
        return {
            "mode": "client",
            "client": {"server_url": "https://example:8443"},
            "security": {"psk": "REPLACE_WITH_GENERATED_PSK"},
        }

    def test_per_user_secret_ignores_placeholder_psk(self):
        cfg = self._base_cfg()
        cfg["user"] = {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "secret": base64.b64encode(bytes(range(32))).decode(),
        }
        tunnel = ClientTunnel(cfg)
        self.assertEqual(tunnel.user_id, cfg["user"]["uuid"])
        self.assertTrue(tunnel.device_id)
        self.assertTrue(tunnel.enc_key and tunnel.hmac_key)

    def test_invalid_psk_without_user_raises_clear_error(self):
        cfg = self._base_cfg()
        with self.assertRaises(ValueError) as ctx:
            ClientTunnel(cfg)
        self.assertIn("security.psk", str(ctx.exception))

    def test_url_status_flags_and_reset(self):
        cfg = self._base_cfg()
        cfg["user"] = {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "secret": base64.b64encode(bytes(range(32))).decode(),
        }
        cfg["client"]["server_urls"] = ["https://a.example", "https://b.example"]
        cfg["client"]["disabled_urls"] = ["https://b.example"]
        tunnel = ClientTunnel(cfg)
        status = {s["url"]: s for s in tunnel.url_status()}
        self.assertTrue(status["https://a.example"]["enabled"])
        self.assertFalse(status["https://b.example"]["enabled"])
        self.assertIn("https://b.example", tunnel.disabled_urls)
        self.assertNotIn("https://b.example", tunnel.server_urls)

        tunnel._url_failures["https://a.example"] = 2
        tunnel._url_cooldown_until["https://a.example"] = time.time() + 30
        state = {s["url"]: s for s in tunnel.url_status()}["https://a.example"]
        self.assertTrue(state["quarantined"])
        self.assertEqual(state["errors"], 2)
        tunnel.reset_url_status()
        self.assertFalse({s["url"]: s for s in tunnel.url_status()}["https://a.example"]["quarantined"])

    def test_set_disabled_urls_live(self):
        cfg = self._base_cfg()
        cfg["user"] = {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "secret": base64.b64encode(bytes(range(32))).decode(),
        }
        cfg["client"]["server_urls"] = ["https://a.example", "https://b.example"]
        tunnel = ClientTunnel(cfg)
        tunnel.set_disabled_urls(["https://a.example"])
        self.assertEqual(tunnel.server_urls, ["https://b.example"])
        tunnel.set_disabled_urls([])
        self.assertEqual(tunnel.server_urls, ["https://a.example", "https://b.example"])

    def test_log_callback_and_default_logger(self):
        cfg = self._base_cfg()
        cfg["user"] = {
            "uuid": "11111111-2222-3333-4444-555555555555",
            "secret": base64.b64encode(bytes(range(32))).decode(),
        }
        tunnel = ClientTunnel(cfg)
        seen = []
        tunnel.set_log_callback(seen.append)
        tunnel.log("hello")
        self.assertEqual(seen, ["hello"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
