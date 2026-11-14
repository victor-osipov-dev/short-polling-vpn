import unittest

from split_routing import Ruleset, SplitRouter
from subscription import apply_subscription


class RulesetTest(unittest.TestCase):
    def setUp(self):
        self.rules = Ruleset(
            ru_cidrs=["5.255.255.0/24"],
            ru_domains=["ru", "yandex.ru"],
            direct_domains=["localhost"],
        )

    def test_ip(self):
        self.assertEqual(self.rules.classify("5.255.255.10"), "ru")
        self.assertEqual(self.rules.classify("8.8.8.8"), "non_ru")
        self.assertEqual(self.rules.classify("192.168.1.1"), "private")
        self.assertEqual(self.rules.classify("127.0.0.1"), "private")

    def test_domains(self):
        self.assertEqual(self.rules.classify("yandex.ru"), "ru")
        self.assertEqual(self.rules.classify("sub.yandex.ru"), "ru")
        self.assertEqual(self.rules.classify("example.ru"), "ru")
        self.assertEqual(self.rules.classify("google.com"), "non_ru")
        self.assertEqual(self.rules.classify("localhost"), "private")


class SplitRouterTest(unittest.TestCase):
    def setUp(self):
        self.cfg = {
            "client": {"server_urls": ["https://ru", "https://eu"]},
            "nodes": [
                {"id": "ru-1", "url": "https://ru"},
                {"id": "eu-1", "url": "https://eu"},
            ],
            "profiles": [{
                "name": "P",
                "routes": [
                    {"name": "RU", "hops": [{"candidates": ["ru-1"]}]},
                    {"name": "EU", "hops": [{"candidates": ["eu-1"], "strategy": "round"}]},
                ],
            }],
            "split_routing": {
                "enabled": True,
                "default": "non_ru",
                "actions": {
                    "ru": {"route": "RU"},
                    "non_ru": {"route": "EU"},
                    "private": {"direct": True},
                },
                "rules": {"ru_domains": ["ru"], "direct_domains": ["localhost"]},
            },
        }
        self.router = SplitRouter(self.cfg)

    def test_routes(self):
        self.assertEqual(self.router.route_for("yandex.ru"), ("tunnel", "https://ru", (), "ru"))
        self.assertEqual(self.router.route_for("google.com"), ("tunnel", "https://eu", (), "non_ru"))
        self.assertEqual(self.router.route_for("192.168.1.1")[0], "direct")

    def test_disabled(self):
        cfg = dict(self.cfg)
        cfg["split_routing"] = dict(cfg["split_routing"], enabled=False)
        router = SplitRouter(cfg)
        self.assertEqual(router.route_for("yandex.ru"), ("tunnel", None, (), None))


class SubscriptionTest(unittest.TestCase):
    def test_apply(self):
        cfg = {"user": {"device_id": "dev-1"}, "client": {}}
        sub = {
            "user": {"uuid": "u-1", "secret": "secret"},
            "nodes": [{"id": "ru-1", "url": "https://ru"}],
            "profiles": [{"name": "P", "routes": []}],
            "split_routing": {"enabled": True},
            "subscription": {"auto_update_hours": 6},
        }
        apply_subscription(cfg, sub)
        self.assertEqual(cfg["user"]["uuid"], "u-1")
        self.assertEqual(cfg["user"]["device_id"], "dev-1")
        self.assertEqual(cfg["client"]["server_urls"], ["https://ru"])
        self.assertTrue(cfg["split_routing"]["enabled"])

    def test_routing_override(self):
        cfg = {
            "routing": {"enabled": True, "ru": "RU route", "private": "direct"},
            "client": {},
        }
        sub = {
            "user": {"uuid": "u", "secret": "s"},
            "nodes": [{"id": "ru-1", "url": "https://ru"}],
            "split_routing": {"enabled": False, "actions": {"non_ru": {"route": "DE"}}},
        }
        apply_subscription(cfg, sub)
        split = cfg["split_routing"]
        self.assertTrue(split["enabled"])
        self.assertEqual(split["actions"]["ru"], {"route": "RU route"})
        self.assertEqual(split["actions"]["non_ru"], {"route": "DE"})
        self.assertEqual(split["actions"]["private"], {"direct": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
