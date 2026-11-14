import unittest

from split_routing import Ruleset, SplitRouter, validate_route_hops
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

    def test_top_level_routes_catalog(self):
        cfg = dict(self.cfg)
        cfg.pop("profiles")
        cfg["routes"] = [
            {"name": "RU", "hops": [{"candidates": ["ru-1"]}]},
            {"name": "EU", "hops": [{"candidates": ["eu-1"]}]},
        ]
        router = SplitRouter(cfg)
        self.assertEqual(router.route_for("yandex.ru"), ("tunnel", "https://ru", (), "ru"))
        self.assertEqual(router.route_for("google.com"), ("tunnel", "https://eu", (), "non_ru"))

    def test_disabled(self):
        cfg = dict(self.cfg)
        cfg["split_routing"] = dict(cfg["split_routing"], enabled=False)
        router = SplitRouter(cfg)
        self.assertEqual(router.route_for("yandex.ru"), ("tunnel", None, (), None))

    def test_round_avoids_duplicate_nodes(self):
        cfg = dict(self.cfg)
        cfg["routes"] = [{
            "name": "CHAIN",
            "hops": [
                {"candidates": ["ru-1", "eu-1"]},
                {"candidates": ["ru-1", "eu-1"]},
            ],
        }]
        cfg["split_routing"] = dict(cfg["split_routing"],
                                    actions={"non_ru": {"route": "CHAIN"}})
        router = SplitRouter(cfg)
        seen = []
        for _ in range(4):
            _, _, ids, _ = router.route_for("google.com")
            self.assertEqual(len(ids), len(set(ids)))
            seen.append(ids)
        self.assertIn(("ru-1", "eu-1"), seen)
        self.assertIn(("eu-1", "ru-1"), seen)

    def test_random_avoids_duplicate_nodes(self):
        cfg = dict(self.cfg)
        cfg["routes"] = [{
            "name": "CHAIN",
            "hops": [
                {"candidates": ["ru-1", "eu-1"], "strategy": "random"},
                {"candidates": ["ru-1", "eu-1"], "strategy": "random"},
            ],
        }]
        cfg["split_routing"] = dict(cfg["split_routing"],
                                    actions={"non_ru": {"route": "CHAIN"}})
        router = SplitRouter(cfg)
        for _ in range(100):
            _, _, ids, _ = router.route_for("google.com")
            self.assertEqual(len(ids), 2)
            self.assertEqual(len(set(ids)), 2)

    def test_backtracking_skips_entry_needed_as_exit(self):
        cfg = dict(self.cfg)
        cfg["routes"] = [{
            "name": "CHAIN",
            "hops": [
                {"candidates": ["ru-1", "eu-1"]},
                {"candidates": ["ru-1"]},
            ],
        }]
        cfg["split_routing"] = dict(cfg["split_routing"],
                                    actions={"non_ru": {"route": "CHAIN"}})
        router = SplitRouter(cfg)
        self.assertEqual(router.route_for("google.com"), ("tunnel", "https://eu",
                                                          ("eu-1", "ru-1"), "non_ru"))

    def test_impossible_chain_is_shortened_with_warning(self):
        cfg = dict(self.cfg)
        cfg["routes"] = [{
            "name": "CHAIN",
            "hops": [{"candidates": ["ru-1"]}, {"candidates": ["ru-1"]}],
        }]
        cfg["split_routing"] = dict(cfg["split_routing"],
                                    actions={"non_ru": {"route": "CHAIN"}})
        router = SplitRouter(cfg)
        self.assertEqual(router.route_for("google.com"),
                         ("tunnel", "https://ru", (), "non_ru"))

    def test_route_validation(self):
        nodes = {"ru-1": "https://ru", "eu-1": "https://eu"}
        issues = validate_route_hops(
            [{"candidates": ["ru-1", "eu-1"]}, {"candidates": ["ru-1", "eu-1"]}],
            set(nodes), nodes,
        )
        self.assertTrue(any(i["level"] == "warning" for i in issues))
        self.assertFalse(any(i["level"] == "error" for i in issues))

        issues = validate_route_hops(
            [{"candidates": ["ru-1"]}, {"candidates": ["ru-1"]}],
            set(nodes), nodes,
        )
        self.assertTrue(any(i["level"] == "error" for i in issues))

        issues = validate_route_hops(
            [{"candidates": ["unknown"]}], set(nodes), nodes,
        )
        self.assertTrue(any(i["level"] == "error" for i in issues))

    def test_route_error_when_no_candidates(self):
        cfg = dict(self.cfg)
        cfg["client"] = {"server_urls": []}
        cfg["routes"] = [{"name": "CHAIN", "hops": [{"candidates": ["missing"]}]}]
        cfg["split_routing"] = dict(cfg["split_routing"],
                                    actions={"non_ru": {"route": "CHAIN"}})
        router = SplitRouter(cfg)
        route = router.route_for("google.com")
        self.assertEqual(route[0], "error")
        self.assertIn("CHAIN", route[4])


class SubscriptionTest(unittest.TestCase):
    def test_apply(self):
        cfg = {"user": {"device_id": "dev-1"}, "client": {}}
        sub = {
            "user": {"uuid": "u-1", "secret": "secret"},
            "nodes": [{"id": "ru-1", "url": "https://ru"}],
            "profiles": [{"name": "P", "routes": []}],
            "routes": [{"name": "RU", "hops": [{"candidates": ["ru-1"]}]}],
            "split_routing": {"enabled": True},
            "subscription": {"auto_update_hours": 6},
        }
        apply_subscription(cfg, sub)
        self.assertEqual(cfg["user"]["uuid"], "u-1")
        self.assertEqual(cfg["user"]["device_id"], "dev-1")
        self.assertEqual(cfg["client"]["server_urls"], ["https://ru"])
        self.assertEqual(cfg["routes"][0]["name"], "RU")
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
