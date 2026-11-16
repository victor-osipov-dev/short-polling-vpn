"""Тесты TUN-режима (tun_mode.py) и связанных настроек профиля.

Сетевые операции не выполняются: проверяется сборка аргументов tun2proxy,
разбор конфигурации профиля и протокол помощника (JSON-Lines поверх
реального loopback-сокета, но без прав администратора — команды start
не вызываем).
"""

import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import tun_mode  # noqa: E402
from desktop_config import DesktopConfig, default_profile_config  # noqa: E402


class TestProfileVpnBackend(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpn-tun-test-")
        self.cfg = DesktopConfig(self.tmp)

    def test_default_backend_is_tun(self):
        cfg = default_profile_config()
        self.assertEqual(cfg["client"]["tun"]["mtu"], 1500)
        self.assertEqual(cfg["client"]["local_address"], "")

    def test_normalize_backend(self):
        p = self.cfg._normalize_profile({"name": "a"})
        self.assertEqual(p["vpn_backend"], "tun")
        p = self.cfg._normalize_profile({"name": "a", "vpn_backend": "system"})
        self.assertEqual(p["vpn_backend"], "system")
        p = self.cfg._normalize_profile({"name": "a", "vpn_backend": "bogus"})
        self.assertEqual(p["vpn_backend"], "tun")

    def test_backend_survives_reload(self):
        profile = {"id": "p1", "name": "T", "mode": "vpn",
                   "vpn_backend": "system", "config": default_profile_config()}
        self.cfg.add_profile(profile)
        loaded = self.cfg.get_active_profile()
        self.assertEqual(loaded["vpn_backend"], "system")

    def test_engine_config_carries_local_address(self):
        profile = {"id": "p1", "name": "T", "mode": "vpn",
                   "vpn_backend": "tun", "config": default_profile_config()}
        profile["config"]["client"]["local_address"] = "192.168.0.5"
        self.cfg.add_profile(profile)
        engine = self.cfg.engine_config(self.cfg.get_active_profile())
        self.assertEqual(engine["client"]["local_address"], "192.168.0.5")


class TestTunModeHelpers(unittest.TestCase):
    def test_hosts_from_urls(self):
        hosts = tun_mode.hosts_from_urls([
            "https://fimdi.ru", "https://data.fimdi.ru:8443", "https://1.2.3.4",
            "", "not a url",
        ])
        self.assertEqual(hosts, ["fimdi.ru", "data.fimdi.ru", "1.2.3.4"])

    def test_resolve_ipv4_literal(self):
        self.assertEqual(tun_mode.resolve_ipv4(["127.0.0.1"]), ["127.0.0.1"])

    def test_looks_virtual(self):
        self.assertTrue(tun_mode._looks_virtual("sing-tun Tunnel"))
        self.assertTrue(tun_mode._looks_virtual("Wintun Userspace Tunnel"))
        self.assertFalse(tun_mode._looks_virtual("Intel(R) Ethernet Connection"))

    def test_build_argv(self):
        proc = tun_mode.TunProcess()
        with mock.patch.object(tun_mode, "tun2proxy_path",
                               return_value=tun_mode.Path("C:/x/tun2proxy-bin.exe")):
            argv = proc.build_argv("127.0.0.1", 8888, mtu=1400, dns_mode="virtual",
                                   bypass_ips=["1.2.3.4", ""], verbosity="debug",
                                   tun_name="vpnclient")
        self.assertIn("--setup", argv)
        self.assertIn("socks5://127.0.0.1:8888", argv)
        self.assertIn("--mtu", argv)
        self.assertEqual(argv[argv.index("--mtu") + 1], "1400")
        self.assertEqual(argv[argv.index("--dns") + 1], "virtual")
        self.assertEqual(argv[argv.index("--tun") + 1], "vpnclient")
        self.assertEqual(argv.count("--bypass"), 1)
        self.assertEqual(argv[argv.index("--bypass") + 1], "1.2.3.4")
        self.assertEqual(argv[argv.index("--verbosity") + 1], "debug")

    def test_build_argv_without_tun_name(self):
        with mock.patch.object(tun_mode, "tun2proxy_path",
                               return_value=tun_mode.Path("C:/x/tun2proxy-bin.exe")):
            argv = tun_mode.TunProcess().build_argv("127.0.0.1", 8888)
        self.assertNotIn("--tun", argv)

    def test_literal_ips_from_urls(self):
        ips = tun_mode.literal_ips_from_urls([
            "https://1.2.3.4", "https://5.6.7.8:8443/", "https://fimdi.ru",
            "https://999.1.1.1", "",
        ])
        self.assertEqual(ips, ["1.2.3.4", "5.6.7.8"])

    def test_as_list(self):
        self.assertEqual(tun_mode._as_list(None), [])
        self.assertEqual(tun_mode._as_list("1.1.1.1, 8.8.8.8"), ["1.1.1.1", "8.8.8.8"])
        self.assertEqual(tun_mode._as_list(["1.1.1.1", ["2.2.2.2"]]),
                         ["1.1.1.1", "2.2.2.2"])

    def test_detect_physical_adapter_skips_virtual(self):
        payload = json.dumps({
            "alias": "singbox_tun", "ip": "172.18.0.1",
            "desc": "sing-tun Tunnel", "static": "", "effective": [],
        })
        with mock.patch.object(tun_mode, "_run_powershell", return_value=payload):
            adapter = tun_mode.detect_physical_adapter()
        # Виртуальный адаптер отброшен; запасной путь тоже не находится
        # (в тесте нет маршрута наружу) — поэтому None либо физический IP.
        self.assertTrue(adapter is None or adapter["alias"] != "singbox_tun")

    def test_detect_physical_adapter_parses(self):
        payload = json.dumps({
            "alias": "Wi-Fi", "ip": "192.168.0.10",
            "desc": "TP-Link Wireless", "static": "1.1.1.1",
            "effective": ["1.1.1.1"],
        })
        with mock.patch.object(tun_mode, "_run_powershell", return_value=payload):
            adapter = tun_mode.detect_physical_adapter()
        self.assertEqual(adapter["alias"], "Wi-Fi")
        self.assertEqual(adapter["static"], "1.1.1.1")
        self.assertEqual(adapter["effective"], ["1.1.1.1"])

    def test_detect_physical_adapter_skips_our_own_tun(self):
        payload = json.dumps([
            {"alias": "vpnclient", "ip": "10.0.0.33", "desc": "Wintun",
             "static": "", "effective": ["10.0.0.1"]},
            {"alias": "Wi-Fi", "ip": "192.168.0.10", "desc": "TP-Link Wireless",
             "static": "", "effective": ["192.168.0.1"]},
        ])
        with mock.patch.object(tun_mode, "_run_powershell", return_value=payload):
            adapter = tun_mode.detect_physical_adapter()
        self.assertEqual(adapter["alias"], "Wi-Fi")
        self.assertEqual(adapter["ip"], "192.168.0.10")

    def test_detect_physical_adapter_prefers_alias(self):
        payload = json.dumps([
            {"alias": "Ethernet", "ip": "192.168.1.5", "desc": "Intel I219",
             "static": "", "effective": []},
            {"alias": "Wi-Fi", "ip": "192.168.0.10", "desc": "TP-Link Wireless",
             "static": "", "effective": []},
        ])
        with mock.patch.object(tun_mode, "_run_powershell", return_value=payload):
            adapter = tun_mode.detect_physical_adapter(prefer_alias="Wi-Fi")
        self.assertEqual(adapter["alias"], "Wi-Fi")

    def test_build_argv_requires_binary(self):
        with mock.patch.object(tun_mode, "tun2proxy_path", return_value=None):
            with self.assertRaises(FileNotFoundError):
                tun_mode.TunProcess().build_argv("127.0.0.1", 8888)

    def test_pick_free_port(self):
        port = tun_mode.pick_free_port()
        self.assertGreater(port, 0)

    def test_tun_available_on_non_windows(self):
        with mock.patch.object(tun_mode, "IS_WINDOWS", False):
            self.assertFalse(tun_mode.tun_available())


class TestHelperProtocol(unittest.TestCase):
    """Протокол помощника: hello/токен/ping/unknown, без start."""

    def setUp(self):
        self.token = "secret-token"
        self.port = tun_mode.pick_free_port()
        self.thread = threading.Thread(
            target=tun_mode.run_helper_server,
            args=(self.port, self.token, 30.0),
            daemon=True,
        )
        self.thread.start()
        self._wait_port()

    def _wait_port(self):
        deadline = time.time() + 5
        while time.time() < deadline:
            try:
                s = socket.create_connection(("127.0.0.1", self.port), timeout=0.3)
                s.close()
                return
            except OSError:
                time.sleep(0.05)
        self.fail("helper did not start")

    def tearDown(self):
        try:
            client = tun_mode.TunHelperClient()
            client.connect(self.port, self.token, allow_launch=False)
            client.quit()
        except Exception:
            pass

    def test_hello_and_ping(self):
        client = tun_mode.TunHelperClient()
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        resp = client.ping()
        self.assertTrue(resp["ok"])
        self.assertFalse(resp["running"])  # start не вызывали
        client.quit()

    def test_bad_token_rejected(self):
        client = tun_mode.TunHelperClient()
        self.assertFalse(client.connect(self.port, "wrong", allow_launch=False))

    def test_unknown_command(self):
        client = tun_mode.TunHelperClient()
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        resp = client._request("nonsense")
        self.assertFalse(resp["ok"])
        self.assertIn("unknown", resp["error"])
        client.quit()

    def test_log_is_forwarded(self):
        lines = []
        client = tun_mode.TunHelperClient(on_log=lines.append)
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        # quit() пишет "tun2proxy остановлен" через лог-колбэк? Нет — но
        # stop() без запущенного процесса только логирует, поэтому вызовем
        # stop_tun и подождём доставки log-сообщения.
        client.stop_tun()
        deadline = time.time() + 3
        while time.time() < deadline and not lines:
            time.sleep(0.05)
        client.quit()
        self.assertTrue(lines, "helper log lines should reach the client")

    def test_connect_is_idempotent(self):
        client = tun_mode.TunHelperClient()
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        sock = client._sock
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        self.assertIs(client._sock, sock)
        self.assertTrue(client.ping()["ok"])
        client.quit()

    def test_matches_port_and_token(self):
        client = tun_mode.TunHelperClient()
        self.assertTrue(client.connect(self.port, self.token, allow_launch=False))
        self.assertTrue(client.matches(self.port, self.token))
        self.assertFalse(client.matches(self.port, "other"))
        self.assertFalse(client.matches(self.port + 1, self.token))
        client.quit()


@unittest.skipUnless(tun_mode.IS_WINDOWS, "ShellExecuteW is Windows-only")
class TestHelperLaunch(unittest.TestCase):
    """Параметры запуска elevated-помощника (без реального UAC)."""

    def _capture(self, kind: str, idle_timeout: float = 600.0) -> dict:
        recorded: dict = {}

        def fake_shell(_hwnd, verb, exe, params, _cwd, _show):
            recorded.update(verb=verb, exe=exe, params=params)
            return 42  # ShellExecuteW: > 32 — успех

        with mock.patch.object(tun_mode, "_python_for_helper",
                               return_value=("C:/x/VPN Client.exe", kind)), \
                mock.patch.object(tun_mode.ctypes.windll.shell32,
                                  "ShellExecuteW", side_effect=fake_shell):
            tun_mode.launch_elevated_helper(41417, "tok", idle_timeout=idle_timeout)
        return recorded

    def test_frozen_passes_tun_helper_and_idle_timeout(self):
        rec = self._capture("frozen")
        self.assertEqual(rec["verb"], "runas")
        self.assertEqual(rec["exe"], "C:/x/VPN Client.exe")
        self.assertIn("--tun-helper", rec["params"])
        self.assertIn("--port 41417", rec["params"])
        self.assertIn('--token "tok"', rec["params"])
        self.assertIn("--idle-timeout 600", rec["params"])

    def test_script_mode_passes_helper_script(self):
        rec = self._capture("script")
        self.assertIn("vpn_helper.py", rec["params"])
        self.assertIn("--port 41417", rec["params"])
        self.assertIn("--idle-timeout 600", rec["params"])

    def test_zero_idle_timeout_is_omitted(self):
        rec = self._capture("frozen", idle_timeout=0)
        self.assertNotIn("--idle-timeout", rec["params"])

    def test_launch_failure_raises(self):
        with mock.patch.object(tun_mode, "_python_for_helper",
                               return_value=("C:/x/VPN Client.exe", "frozen")), \
                mock.patch.object(tun_mode.ctypes.windll.shell32,
                                  "ShellExecuteW", return_value=5):
            with self.assertRaises(PermissionError):
                tun_mode.launch_elevated_helper(41417, "tok")


class TestDnsHijack(unittest.TestCase):
    """Переключение и восстановление DNS без реальных изменений системы."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="vpn-dns-test-")
        self.state_file = tun_mode.Path(self.tmp) / "state.json"
        self._orig_state = tun_mode.DNS_STATE_FILE
        tun_mode.DNS_STATE_FILE = self.state_file

    def tearDown(self):
        tun_mode.DNS_STATE_FILE = self._orig_state

    def test_hijack_writes_state_and_sets_tun_gateway(self):
        adapter = {"alias": "Wi-Fi", "ip": "192.168.0.10", "desc": "TP-Link",
                   "static": "", "effective": ["192.168.0.1"]}
        calls = []
        with mock.patch.object(tun_mode, "_set_interface_dns",
                               side_effect=lambda a, s: calls.append((a, s)) or True):
            state = tun_mode.hijack_dns_to_tun(adapter)
        self.assertEqual(calls, [("Wi-Fi", [tun_mode.TUN_GATEWAY])])
        self.assertEqual(state["alias"], "Wi-Fi")
        self.assertTrue(self.state_file.is_file())

    def test_hijack_failure_drops_state(self):
        adapter = {"alias": "Wi-Fi", "ip": "192.168.0.10", "desc": "TP-Link",
                   "static": "", "effective": []}
        with mock.patch.object(tun_mode, "_set_interface_dns", return_value=False):
            self.assertIsNone(tun_mode.hijack_dns_to_tun(adapter))
        self.assertFalse(self.state_file.is_file())

    def test_restore_uses_saved_static(self):
        self.state_file.write_text(json.dumps({
            "alias": "Wi-Fi", "static": "1.1.1.1 8.8.8.8", "effective": [],
        }), encoding="utf-8")
        calls = []
        with mock.patch.object(tun_mode, "_set_interface_dns",
                               side_effect=lambda a, s: calls.append((a, s)) or True):
            self.assertTrue(tun_mode.restore_dns_from_state())
        self.assertEqual(calls, [("Wi-Fi", ["1.1.1.1", "8.8.8.8"])])
        self.assertFalse(self.state_file.is_file())

    def test_restore_falls_back_to_dhcp(self):
        self.state_file.write_text(json.dumps({
            "alias": "Wi-Fi", "static": "", "effective": ["192.168.0.1"],
        }), encoding="utf-8")
        called = []
        with mock.patch.object(tun_mode, "_reset_interface_dns",
                               side_effect=lambda a: called.append(a) or True):
            self.assertTrue(tun_mode.restore_dns_from_state())
        self.assertEqual(called, ["Wi-Fi"])

    def test_restore_without_state_is_noop(self):
        self.assertFalse(tun_mode.restore_dns_from_state())


if __name__ == "__main__":
    unittest.main(verbosity=2)
