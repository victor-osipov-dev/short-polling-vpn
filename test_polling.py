"""Тесты адаптивного интервала опроса (tunnel.ClientTunnel._poll_delay_ms)."""

import time
import unittest
from types import SimpleNamespace

from tunnel import ClientTunnel


def make_tunnel(**overrides):
    state = {
        "_outbox": {},
        "sessions": {},
        "_last_activity": time.monotonic(),
        "poll_interval_ms": 100,
        "poll_idle_ms": 800,
        "poll_min_ms": 100,
        "poll_active_window_ms": 1500,
        "poll_jitter_ms": 0,
    }
    state.update(overrides)
    return SimpleNamespace(**state)


class PollDelayTest(unittest.TestCase):
    def delay(self, tunnel):
        return ClientTunnel._poll_delay_ms(tunnel)

    def test_active_uses_short_interval(self):
        self.assertEqual(self.delay(make_tunnel()), 100)

    def test_idle_uses_long_interval(self):
        tunnel = make_tunnel(_last_activity=time.monotonic() - 10)
        self.assertEqual(self.delay(tunnel), 800)

    def test_min_floor_wins(self):
        tunnel = make_tunnel(poll_interval_ms=20)
        self.assertEqual(self.delay(tunnel), 100)

    def test_pending_outgoing_keeps_active(self):
        tunnel = make_tunnel(
            _last_activity=time.monotonic() - 10,
            sessions={"s": SimpleNamespace(outgoing=bytearray(b"x"), pending_new=None)},
        )
        self.assertEqual(self.delay(tunnel), 100)

    def test_pending_new_keeps_active(self):
        tunnel = make_tunnel(
            _last_activity=time.monotonic() - 10,
            sessions={"s": SimpleNamespace(outgoing=bytearray(), pending_new=object())},
        )
        self.assertEqual(self.delay(tunnel), 100)

    def test_idle_ceiling_cannot_go_below_floor(self):
        tunnel = make_tunnel(
            _last_activity=time.monotonic() - 10,
            poll_idle_ms=50,
        )
        self.assertEqual(self.delay(tunnel), 100)

    def test_open_session_stays_active(self):
        # Открытое соединение ждёт входящих данных — переход в idle увеличил бы
        # задержку доставки ответа (например, SSE) до poll_idle_ms.
        tunnel = make_tunnel(
            _last_activity=time.monotonic() - 10,
            sessions={"s": SimpleNamespace(outgoing=bytearray(), pending_new=None)},
        )
        self.assertEqual(self.delay(tunnel), 100)

if __name__ == "__main__":
    unittest.main()
