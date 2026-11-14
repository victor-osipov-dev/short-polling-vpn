"""Быстрые тесты хранилища и панели (без сети)."""

import json
import os
import re
import tempfile
import threading
import unittest
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from http.server import ThreadingHTTPServer

from admin.store import Store
from admin.panel import Panel, Handler, hash_password


class StoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = Store(
            os.path.join(self.tmp.name, "vpn.db"),
            os.path.join(self.tmp.name, "cluster.key"),
            node_id="test-master",
        )

    def tearDown(self):
        self.store.close()
        self.tmp.cleanup()

    def test_user_secret_and_subscription(self):
        user, secret = self.store.create_user("Alice")
        self.assertEqual(len(secret), 32)
        self.assertEqual(self.store.get_secret(user.uuid), secret)
        self.assertIsNone(self.store.get_user("missing"))
        token = self.store.subscription_token(user.uuid)
        self.assertTrue(token)
        self.assertEqual(self.store.get_user_by_token(token).uuid, user.uuid)

    def test_devices_and_limit(self):
        user, _ = self.store.create_user("Bob", max_devices=1)
        ok, reason = self.store.register_device(user.uuid, "dev-1")
        self.assertTrue(ok, reason)
        ok, reason = self.store.register_device(user.uuid, "dev-2")
        self.assertFalse(ok)
        self.assertEqual(reason, "device_limit")
        self.assertEqual(len(self.store.list_devices(user.uuid)), 1)

    def test_disable_and_delete(self):
        user, _ = self.store.create_user("Carol")
        self.store.register_device(user.uuid, "dev-1")
        self.store.set_enabled(user.uuid, False)
        self.assertFalse(self.store.get_user(user.uuid).enabled)
        ok, reason = self.store.register_device(user.uuid, "dev-2")
        self.assertFalse(ok)
        self.assertEqual(reason, "disabled")
        self.assertTrue(self.store.delete_user(user.uuid))
        self.assertIsNone(self.store.get_user(user.uuid))
        self.assertEqual(self.store.list_devices(user.uuid), [])
        row = self.store.conn.execute(
            "SELECT * FROM tombstones WHERE uuid=?", (user.uuid,)
        ).fetchone()
        self.assertIsNotNone(row)

    def test_rotate_secret(self):
        user, old = self.store.create_user("Dave")
        new = self.store.rotate_secret(user.uuid)
        self.assertNotEqual(old, new)
        self.assertEqual(self.store.get_secret(user.uuid), new)


class PanelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = {
            "db_path": os.path.join(self.tmp.name, "vpn.db"),
            "cluster_key": os.path.join(self.tmp.name, "cluster.key"),
            "node_id": "test-master",
            "admin_username": "admin",
            "admin_password_hash": hash_password("testpass"),
            "public_base_url": "https://example.test:8443",
            "rules_dir": os.path.join(self.tmp.name, "rules"),
            "subscription": {
                "nodes": [{"id": "ru-1", "url": "https://example.test:8443"}],
                "split_routing": {"rules": {"geoip": "geoip-ru.txt"}},
            },
        }
        os.makedirs(self.cfg["rules_dir"], exist_ok=True)
        with open(os.path.join(self.cfg["rules_dir"], "geoip-ru.txt"), "w") as f:
            f.write("5.255.255.0/24\n")
        panel = Panel(self.cfg)
        self.panel = panel
        Handler.panel = panel
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.base = f"http://127.0.0.1:{self.port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.panel.store.close()
        self.tmp.cleanup()

    def get(self, path):
        return self.opener.open(self.base + path, timeout=5)

    def post(self, path, data):
        body = urllib.parse.urlencode(data).encode()
        req = urllib.request.Request(self.base + path, data=body, method="POST")
        return self.opener.open(req, timeout=5)

    def test_flow(self):
        # login
        resp = self.post("/login", {"username": "admin", "password": "testpass"})
        self.assertEqual(resp.status, 200)
        html = resp.read().decode()
        self.assertIn("Пользователи", html)
        self.assertIn("Узлы", self.get("/nodes").read().decode())

        # new user form -> csrf
        form_html = self.get("/users/new").read().decode()
        csrf = re.search(r'name="csrf" value="([^"]+)"', form_html).group(1)

        resp = self.post("/users/new", {
            "csrf": csrf, "name": "Alice", "max_devices": "2",
        })
        self.assertEqual(resp.status, 200)
        users_html = self.get("/users").read().decode()
        uuid = re.search(r"/users/([0-9a-f-]{36})", users_html).group(1)

        sub = json.loads(self.get(f"/users/{uuid}/sub.json").read())
        self.assertEqual(sub["user"]["uuid"], uuid)
        self.assertEqual(len(sub["user"]["secret"]), 43)  # 32 bytes base64url
        self.assertTrue(sub["split_routing"]["rules"]["geoip"].endswith("/rules/geoip-ru.txt"))
        self.assertEqual(self.get("/rules/geoip-ru.txt").read().decode().strip(), "5.255.255.0/24")

        token = sub["subscription"]["url"].rsplit("/", 1)[-1]
        public_sub = json.loads(self.get(f"/sub/{token}").read())
        self.assertEqual(public_sub["user"]["uuid"], uuid)

        # disable -> public sub forbidden
        detail = self.get(f"/users/{uuid}").read().decode()
        csrf2 = re.search(r'name="csrf" value="([^"]+)"', detail).group(1)
        self.post(f"/users/{uuid}/disable", {"csrf": csrf2})
        try:
            self.get(f"/sub/{token}")
            self.fail("disabled subscription must be rejected")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)


class ReplicationTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db1 = os.path.join(self.tmp.name, "one.db")
        self.db2 = os.path.join(self.tmp.name, "two.db")
        self.key = os.path.join(self.tmp.name, "cluster.key")
        self.key2 = os.path.join(self.tmp.name, "cluster2.key")
        self.store1 = Store(self.db1, self.key, node_id="node-1",
                            node_key_path=os.path.join(self.tmp.name, "n1.key"))
        # общий cluster-ключ между мастерами
        with open(self.key, "rb") as f:
            key_bytes = f.read()
        with open(self.key2, "wb") as f:
            f.write(key_bytes)
        self.store2 = Store(self.db2, self.key2, node_id="node-2",
                            node_key_path=os.path.join(self.tmp.name, "n2.key"),
                            peers={"node-1": self.store1.node_public_key()})
        self.store1.peers = {"node-2": self.store2.node_public_key()}

    def tearDown(self):
        self.store1.close()
        self.store2.close()
        self.tmp.cleanup()

    def sync(self, after=0):
        ops = self.store1.export_ops(after)
        result = self.store2.apply_ops(ops)
        return ops, result

    def test_user_replication(self):
        user, secret = self.store1.create_user("Alice", max_devices=2)
        self.store1.register_device(user.uuid, "dev-1", "Pixel")
        ops, result = self.sync()
        self.assertGreater(result["applied"], 0)
        self.assertEqual(result["errors"], 0)
        copied = self.store2.get_user(user.uuid)
        self.assertIsNotNone(copied)
        self.assertEqual(copied.name, "Alice")
        self.assertEqual(self.store2.get_secret(user.uuid), secret)
        self.assertEqual(len(self.store2.list_devices(user.uuid)), 1)
        token = self.store1.subscription_token(user.uuid)
        self.assertEqual(self.store2.get_user_by_token(token).uuid, user.uuid)

        last_hlc = max(op["hlc"] for op in ops)
        self.store1.set_enabled(user.uuid, False)
        ops2, result2 = self.sync(last_hlc)
        self.assertGreater(result2["applied"], 0)
        self.assertFalse(self.store2.get_user(user.uuid).enabled)

        last_hlc = max(op["hlc"] for op in ops + ops2)
        self.store1.delete_user(user.uuid)
        self.sync(last_hlc)
        self.assertIsNone(self.store2.get_user(user.uuid))
        self.assertEqual(self.store2.list_devices(user.uuid), [])

    def test_bad_signature_rejected(self):
        user, _ = self.store1.create_user("Bob")
        ops, _ = self.sync()
        ops[0]["payload"]["name"] = "Mallory"
        result = self.store2.apply_ops([ops[0]])
        self.assertEqual(result["applied"], 0)
        self.assertEqual(result["errors"], 1)

    def test_tombstone_blocks_old_upsert(self):
        user, _ = self.store1.create_user("Carol")
        ops, _ = self.sync()
        last_hlc = max(op["hlc"] for op in ops)
        self.store1.delete_user(user.uuid)
        delete_ops, _ = self.sync(last_hlc)
        self.assertIsNone(self.store2.get_user(user.uuid))
        # старый upsert не должен воскресить пользователя
        self.store2.apply_ops([ops[0]])
        self.assertIsNone(self.store2.get_user(user.uuid))


if __name__ == "__main__":
    unittest.main(verbosity=2)
