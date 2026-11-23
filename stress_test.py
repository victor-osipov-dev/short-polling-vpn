"""Local stress test for the short-polling VPN protocol.

Starts 5 local entry servers plus 1 shared exit server, a local TCP echo
target, and several headless clients.  Every client opens many sessions with
different routing scenarios (single hop, 5-way fan-in to one exit, 3-hop
chains, bulk payload, and a direct baseline).

Run:
    python stress_test.py --clients 4 --per-scenario 15

Results (per-connection CSV, summary JSON and a Markdown report) are written
to stress-results/<timestamp>/.  Nothing touches the production servers.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import os
import shutil
import socket
import statistics
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml

from crypto_utils import generate_psk

ROOT = Path(__file__).resolve().parent
MAIN_PY = ROOT / "main.py"


# ── helpers ────────────────────────────────────────────────────────────────


def port_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.4):
            return True
    except OSError:
        return False


async def wait_port(port: int, timeout: float = 20.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(port):
            return
        await asyncio.sleep(0.15)
    raise RuntimeError(f"port {port} did not open in {timeout:.0f}s")


def percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    pos = (len(ordered) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(ordered) - 1)
    frac = pos - lo
    return ordered[lo] * (1 - frac) + ordered[hi] * frac


def mb(value: int) -> float:
    return value / (1024 * 1024)


# ── synthetic SOCKS writer ─────────────────────────────────────────────────


class SinkWriter:
    """Minimal StreamWriter substitute used to collect tunneled echo data."""

    def __init__(self, on_data):
        self._on_data = on_data
        self.closed = False

    def write(self, data):
        if not self.closed:
            self._on_data(bytes(data))

    async def drain(self):
        return None

    def close(self):
        self.closed = True

    def is_closing(self):
        return self.closed

    def get_extra_info(self, name, default=None):
        return default


# ── local echo target ──────────────────────────────────────────────────────


async def run_echo_server(port: int):
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    server = await asyncio.start_server(handle, "127.0.0.1", port)
    return server


# ── server / client config builders ────────────────────────────────────────


def server_config(node_id: str, port: int, psk: str, relay_secret: str,
                  peers: dict[str, str], max_chunk: int) -> dict:
    return {
        "mode": "server",
        "node_id": node_id,
        "relay_secret": relay_secret,
        "peers": peers,
        "server": {
            "bind_host": "127.0.0.1",
            "bind_port": port,
            "poll_path": "/poll",
            "max_chunk_bytes": max_chunk,
            "idle_timeout_seconds": 600,
        },
        "security": {"psk": psk, "hmac_window_seconds": 60},
        "logging": {"level": "WARNING"},
    }


def client_config(urls: list[str], psk: str, poll_ms: int, max_chunk: int,
                  selector: str) -> dict:
    return {
        "mode": "client",
        "client": {
            "server_urls": urls,
            "server_selector": selector,
            "poll_path": "/poll",
            "poll_interval_ms": poll_ms,
            "poll_jitter_ms": max(1, poll_ms // 5),
            "pad_polls": False,
            "max_chunk_bytes": max_chunk,
            "verify_tls": False,
            "trust_env_proxy": False,
            "poll_method": "POST",
            "poll_data_in": "body",
            "url_fail_limit": 100000,
            "url_cooldown_seconds": 5,
            "idle_timeout": {"enabled": False},
        },
        "security": {"psk": psk, "hmac_window_seconds": 60},
        "split_routing": {"enabled": False},
        "logging": {"level": "WARNING"},
    }


# ── scenario runner ────────────────────────────────────────────────────────

SCENARIOS = ("simple", "fanin_2hop", "chain_3hop", "bulk", "baseline")


async def run_vpn_connection(tunnel, entry_url: str, route: tuple[str, ...],
                             echo_port: int, payload: bytes, timeout: float,
                             client_id: int, scenario: str, index: int) -> dict:
    record: dict[str, Any] = {
        "client": client_id,
        "scenario": scenario,
        "index": index,
        "entry": entry_url,
        "route": ",".join(route) if route else "(single-hop)",
        "bytes": len(payload),
        "status": "ok",
        "latency_ms": 0.0,
        "received": 0,
        "error": "",
    }
    queue: asyncio.Queue[bytes] = asyncio.Queue()
    writer = SinkWriter(queue.put_nowait)
    started = time.perf_counter()
    sid = None
    try:
        sid = await tunnel.register_session(
            writer, "127.0.0.1", echo_port,
            server_base=entry_url, route=route,
        )
        await tunnel.feed_outgoing(sid, payload)
        received = bytearray()
        while len(received) < len(payload):
            chunk = await asyncio.wait_for(queue.get(), timeout=timeout)
            received.extend(chunk)
        record["latency_ms"] = (time.perf_counter() - started) * 1000
        record["received"] = len(received)
        if bytes(received[: len(payload)]) != payload:
            record["status"] = "mismatch"
            record["error"] = "echoed data differs from payload"
    except asyncio.TimeoutError:
        record["status"] = "timeout"
        record["error"] = f"no echo within {timeout}s (got {queue.qsize()} chunks)"
    except Exception as exc:
        record["status"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if sid is not None:
            try:
                await tunnel.mark_closed(sid)
            except Exception:
                pass
        writer.close()
    return record


async def run_baseline(echo_port: int, payload: bytes, timeout: float,
                       client_id: int, index: int) -> dict:
    record: dict[str, Any] = {
        "client": client_id,
        "scenario": "baseline",
        "index": index,
        "entry": "direct TCP",
        "route": "direct",
        "bytes": len(payload),
        "status": "ok",
        "latency_ms": 0.0,
        "received": 0,
        "error": "",
    }
    started = time.perf_counter()
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", echo_port), timeout=timeout
        )
        writer.write(payload)
        await writer.drain()
        received = bytearray()
        while len(received) < len(payload):
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                raise ConnectionError("echo closed early")
            received.extend(chunk)
        record["latency_ms"] = (time.perf_counter() - started) * 1000
        record["received"] = len(received)
        if bytes(received[: len(payload)]) != payload:
            record["status"] = "mismatch"
            record["error"] = "echoed data differs from payload"
    except asyncio.TimeoutError:
        record["status"] = "timeout"
        record["error"] = f"no echo within {timeout}s"
    except Exception as exc:
        record["status"] = "error"
        record["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    return record


async def run_client(client_id: int, cfg: dict, args, urls: dict[str, str],
                     echo_port: int, results: list[dict]) -> dict:
    from tunnel import ClientTunnel

    tunnel = ClientTunnel(cfg)
    poll_task = asyncio.create_task(tunnel.poll_loop())
    semaphore = asyncio.Semaphore(args.concurrency)
    entry_ids = [f"e{i}" for i in range(1, 6)]

    async def limited(coro):
        async with semaphore:
            return await coro

    tasks = []
    for i in range(args.per_scenario):
        for scenario in SCENARIOS:
            if scenario == "simple":
                tasks.append(limited(run_vpn_connection(
                    tunnel, urls["x"], (), echo_port,
                    _payload(args.payload, i), args.timeout,
                    client_id, scenario, i,
                )))
            elif scenario == "fanin_2hop":
                entry = entry_ids[i % 5]
                tasks.append(limited(run_vpn_connection(
                    tunnel, urls[entry], (entry, "x"), echo_port,
                    _payload(args.payload, i), args.timeout,
                    client_id, scenario, i,
                )))
            elif scenario == "chain_3hop":
                entry = entry_ids[(i + client_id) % 5]
                relay = entry_ids[(i + client_id + 1) % 5]
                tasks.append(limited(run_vpn_connection(
                    tunnel, urls[entry], (entry, relay, "x"), echo_port,
                    _payload(args.payload, i), args.timeout,
                    client_id, scenario, i,
                )))
            elif scenario == "bulk":
                tasks.append(limited(run_vpn_connection(
                    tunnel, urls["x"], (), echo_port,
                    _payload(args.bulk_payload, i), args.timeout,
                    client_id, scenario, i,
                )))
            else:
                tasks.append(limited(run_baseline(
                    echo_port, _payload(args.payload, i), args.timeout,
                    client_id, i,
                )))

    done = await asyncio.gather(*tasks, return_exceptions=True)
    for item in done:
        if isinstance(item, Exception):
            rec = {
                "client": client_id, "scenario": "unknown", "index": -1,
                "entry": "", "route": "", "bytes": 0, "status": "error",
                "latency_ms": 0, "received": 0, "error": repr(item),
            }
        else:
            rec = item
        rec["t_offset"] = round(time.perf_counter() - getattr(args, "test_start", time.perf_counter()), 2)
        results.append(rec)

    snapshot = {
        "client": client_id,
        "polls": tunnel._poll_count,
        "sessions": len(tunnel.sessions),
        "url_failures": dict(tunnel._url_failures),
        "server_urls": list(tunnel.server_urls),
    }
    poll_task.cancel()
    try:
        await poll_task
    except asyncio.CancelledError:
        pass
    try:
        await tunnel.http.aclose()
    except Exception:
        pass
    return snapshot


def _payload(size: int, seed: int) -> bytes:
    base = bytes((i % 251 for i in range(size)))
    shift = seed % 251
    return bytes(((b + shift) % 251) for b in base)


# ── reporting ──────────────────────────────────────────────────────────────


def timeline(records: list[dict], bucket: float = 5.0) -> dict:
    groups: dict[int, list[dict]] = {}
    for rec in records:
        key = int(rec.get("t_offset", 0) // bucket)
        groups.setdefault(key, []).append(rec)
    out = {}
    for key, items in sorted(groups.items()):
        ok = [r for r in items if r["status"] == "ok"]
        lat = [r["latency_ms"] for r in ok]
        out[f"{key*bucket:.0f}-{key*bucket+bucket:.0f}s"] = {
            "total": len(items),
            "ok": len(ok),
            "p50": round(percentile(lat, 0.5), 2),
            "p95": round(percentile(lat, 0.95), 2),
            "max": round(max(lat), 2) if lat else 0,
        }
    return out


def aggregate(records: list[dict], key: str) -> dict:
    groups: dict[str, list[dict]] = {}
    for rec in records:
        groups.setdefault(str(rec[key]), []).append(rec)
    out = {}
    for name, items in groups.items():
        ok = [r for r in items if r["status"] == "ok"]
        lat = [r["latency_ms"] for r in ok]
        out[name] = {
            "total": len(items),
            "ok": len(ok),
            "failed": len(items) - len(ok),
            "success_rate": round(len(ok) / len(items) * 100, 2) if items else 0,
            "latency_ms": {
                "min": round(min(lat), 2) if lat else 0,
                "mean": round(statistics.fmean(lat), 2) if lat else 0,
                "p50": round(percentile(lat, 0.5), 2),
                "p90": round(percentile(lat, 0.9), 2),
                "p95": round(percentile(lat, 0.95), 2),
                "p99": round(percentile(lat, 0.99), 2),
                "max": round(max(lat), 2) if lat else 0,
            },
            "bytes": sum(r["bytes"] for r in ok),
            "errors": {
                status: sum(1 for r in items if r["status"] == status)
                for status in {r["status"] for r in items} if status != "ok"
            },
        }
    return out


def write_reports(out_dir: Path, args, records: list[dict], client_stats: list[dict],
                  server_stats: list[dict], duration: float) -> dict:
    summary = {
        "started": datetime.now().isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 2),
        "clients": args.clients,
        "per_scenario": args.per_scenario,
        "concurrency": args.concurrency,
        "servers": args.entries + 1,
        "total_connections": len(records),
        "by_scenario": aggregate(records, "scenario"),
        "by_client": aggregate(records, "client"),
        "timeline_5s": timeline(records),
        "client_stats": client_stats,
        "server_stats": server_stats,
        "errors_by_type": {
            status: sum(1 for r in records if r["status"] == status)
            for status in {r["status"] for r in records} if status != "ok"
        },
    }
    (out_dir / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    with (out_dir / "connections.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(records[0].keys()))
        writer.writeheader()
        writer.writerows(records)

    def table(data: dict) -> str:
        lines = [
            "| Группа | Всего | OK | Ошибок | Успех % | p50 мс | p95 мс | p99 мс | Max мс |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
        for name, st in data.items():
            lt = st["latency_ms"]
            lines.append(
                f"| {name} | {st['total']} | {st['ok']} | {st['failed']} | "
                f"{st['success_rate']} | {lt['p50']} | {lt['p95']} | {lt['p99']} | {lt['max']} |"
            )
        return "\n".join(lines)

    timeline_lines = [
        "| Интервал | Всего | OK | p50 мс | p95 мс | Max мс |",
        "| --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for name, st in summary["timeline_5s"].items():
        timeline_lines.append(
            f"| {name} | {st['total']} | {st['ok']} | {st['p50']} | {st['p95']} | {st['max']} |"
        )
    timeline_table = "\n".join(timeline_lines)

    err_lines = []
    for status, count in summary["errors_by_type"].items():
        samples = [r["error"] for r in records if r["status"] == status and r["error"]][:3]
        err_lines.append(f"- **{status}**: {count} — {'; '.join(samples) or 'нет деталей'}")
    if not err_lines:
        err_lines.append("- Ошибок нет.")

    srv_lines = [
        f"- `{s['node_id']}` ({s['port']}): CPU {s['cpu_seconds']:.2f}s, RSS {mb(s['rss_mb']*1024*1024):.1f} MB"
        for s in server_stats
    ]

    md = f"""# Local VPN protocol stress test

Дата: {summary['started']}
Длительность: **{duration:.1f} с**
Клиентов: **{args.clients}**, соединений на сценарий на клиента: **{args.per_scenario}**,
параллелизм на клиента: **{args.concurrency}**, серверов: **{args.entries + 1}** (5 entry + 1 exit).
Всего соединений: **{len(records)}**.

## Сценарии

- `simple` — один хоп напрямую на exit-узел, без X-Route.
- `fanin_2hop` — вход на один из 5 entry-узлов, релей на общий exit (`eN → x`).
- `chain_3hop` — цепочка из трёх узлов (`eN → eM → x`), все выходят на один exit.
- `bulk` — один хоп, полезная нагрузка {args.bulk_payload} байт.
- `baseline` — прямой TCP к echo-серверу без VPN (для сравнения задержек).

## Результаты по сценариям

{table(summary['by_scenario'])}

## Результаты по клиентам

{table(summary['by_client'])}

## Динамика по 5-секундным интервалам

{timeline_table}

## Ошибки

{chr(10).join(err_lines)}

## Нагрузка на серверы

{chr(10).join(srv_lines)}

## Статистика клиентских туннелей

{json.dumps(client_stats, ensure_ascii=False, indent=2)}

## Файлы

- `connections.csv` — по каждой сессии: сценарий, entry, цепочка, задержка, байты, статус.
- `summary.json` — полные метрики.
- `configs/` — конфиги всех серверов и клиентов.
- `server-logs/` — stdout/stderr локальных серверов.
"""
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    return summary


# ── main ───────────────────────────────────────────────────────────────────


async def run(args) -> int:
    out_dir = Path(args.output).resolve() / datetime.now().strftime("%Y%m%d-%H%M%S")
    configs_dir = out_dir / "configs"
    logs_dir = out_dir / "server-logs"
    configs_dir.mkdir(parents=True, exist_ok=True)
    logs_dir.mkdir(parents=True, exist_ok=True)

    for port in [args.echo_port, args.exit_port] + [
        args.base_port + i for i in range(1, args.entries + 1)
    ]:
        if port_open(port):
            raise RuntimeError(f"port {port} is already in use; choose different --base-port/--exit-port/--echo-port")

    psk = generate_psk()
    relay_secret = f"stress-relay-{int(time.time())}"

    entry_ids = [f"e{i}" for i in range(1, args.entries + 1)]
    entry_ports = {nid: args.base_port + i for i, nid in enumerate(entry_ids, 1)}
    urls = {nid: f"http://127.0.0.1:{port}" for nid, port in entry_ports.items()}
    urls["x"] = f"http://127.0.0.1:{args.exit_port}"

    peers = {nid: urls[nid] for nid in entry_ids}
    peers["x"] = urls["x"]
    server_specs = []
    for nid in entry_ids:
        server_specs.append((nid, entry_ports[nid],
                             server_config(nid, entry_ports[nid], psk, relay_secret,
                                           peers, args.server_chunk)))
    server_specs.append(("x", args.exit_port,
                         server_config("x", args.exit_port, psk, relay_secret,
                                       {}, args.server_chunk)))

    for name, _port, cfg in server_specs:
        (configs_dir / f"server-{name}.yaml").write_text(
            yaml.safe_dump(cfg, sort_keys=False, allow_unicode=True), encoding="utf-8"
        )

    procs: list[subprocess.Popen] = []
    log_files = []
    try:
        echo = await run_echo_server(args.echo_port)
        for name, _port, cfg in server_specs:
            log_path = logs_dir / f"server-{name}.log"
            handle = log_path.open("wb")
            log_files.append(handle)
            proc = subprocess.Popen(
                [sys.executable, str(MAIN_PY), "--config",
                 str(configs_dir / f"server-{name}.yaml")],
                cwd=str(ROOT), stdout=handle, stderr=subprocess.STDOUT,
            )
            procs.append(proc)

        await asyncio.gather(*(wait_port(port) for _n, port, _c in server_specs))

        client_stats: list[dict] = []
        records: list[dict] = []
        all_urls = [urls[nid] for nid in entry_ids] + [urls["x"]]
        started = time.perf_counter()
        args.test_start = started
        for i in range(args.clients):
            client_cfg = client_config(
                all_urls, psk, args.poll_ms, args.client_chunk,
                selector="round" if i % 2 == 0 else "random",
            )
            (configs_dir / f"client-{i}.yaml").write_text(
                yaml.safe_dump(client_cfg, sort_keys=False, allow_unicode=True), encoding="utf-8"
            )
            client_stats.append(await run_client(
                i, client_cfg, args, urls, args.echo_port, records
            ))
        duration = time.perf_counter() - started

        try:
            import psutil
            server_stats = []
            for (name, port, _cfg), proc in zip(server_specs, procs):
                try:
                    p = psutil.Process(proc.pid)
                    cpu = sum(p.cpu_times()[:2])
                    rss = p.memory_info().rss
                except Exception:
                    cpu, rss = 0.0, 0
                server_stats.append({
                    "node_id": name, "port": port,
                    "cpu_seconds": round(cpu, 2), "rss_mb": round(rss / 1048576, 1),
                })
        except ImportError:
            server_stats = []

        summary = write_reports(out_dir, args, records, client_stats, server_stats, duration)
        print(f"\nResults: {out_dir / 'report.md'}")
        print(f"Total {summary['total_connections']} connections in {duration:.1f}s")
        for name, st in summary["by_scenario"].items():
            lt = st["latency_ms"]
            print(f"  {name:12} ok={st['ok']:4}/{st['total']:<4} "
                  f"p50={lt['p50']:7.2f}ms p95={lt['p95']:7.2f}ms p99={lt['p99']:7.2f}ms")
        echo.close()
        await echo.wait_closed()
        return 0
    finally:
        for proc in procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for handle in log_files:
            try:
                handle.close()
            except Exception:
                pass


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--clients", type=int, default=4, help="number of headless clients")
    p.add_argument("--per-scenario", type=int, default=15,
                   help="connections per scenario per client")
    p.add_argument("--concurrency", type=int, default=8,
                   help="max simultaneous connections per client")
    p.add_argument("--poll-ms", type=int, default=25, help="client poll interval")
    p.add_argument("--payload", type=int, default=512, help="payload bytes for most scenarios")
    p.add_argument("--bulk-payload", type=int, default=32768, help="payload bytes for bulk scenario")
    p.add_argument("--timeout", type=float, default=15.0, help="per-connection timeout")
    p.add_argument("--entries", type=int, default=5, help="number of entry servers")
    p.add_argument("--base-port", type=int, default=9100,
                   help="entry servers use base-port+1..base-port+N")
    p.add_argument("--exit-port", type=int, default=9110, help="shared exit server port")
    p.add_argument("--echo-port", type=int, default=9700, help="local TCP echo target")
    p.add_argument("--client-chunk", type=int, default=16384, help="client max_chunk_bytes")
    p.add_argument("--server-chunk", type=int, default=65536, help="server max_chunk_bytes")
    p.add_argument("--output", default="stress-results", help="results directory")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.clients < 1 or args.per_scenario < 1 or args.concurrency < 1:
        raise SystemExit("clients, per-scenario and concurrency must be >= 1")
    if args.bulk_payload < 1 or args.payload < 1:
        raise SystemExit("payload sizes must be >= 1")
    try:
        code = asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\nInterrupted")
        code = 130
    raise SystemExit(code)


if __name__ == "__main__":
    main()
