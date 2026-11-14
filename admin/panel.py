"""Веб-панель администратора (только 127.0.0.1 + SSH-туннель).

Запуск:
    python -m admin.panel --config admin/config.yaml
    python -m admin.panel --hash-password 'secret'
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import html
import io
import json
import os
import re
import secrets
import ssl
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

try:
    from .store import Store, User, b64e
except ImportError:  # запуск из каталога admin/
    from store import Store, User, b64e


# ── пароль ───────────────────────────────────────────────────────────

def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(password: str, encoded: str) -> bool:
    try:
        _, salt_b64, hash_b64 = encoded.split("$", 2)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        dk = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


# ── сессии ───────────────────────────────────────────────────────────

class Sessions:
    def __init__(self, ttl_hours: int = 12):
        self.ttl = ttl_hours * 3600
        self.lock = threading.Lock()
        self.data: dict[str, dict] = {}

    def create(self, username: str) -> tuple[str, str]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        with self.lock:
            self.data[token] = {
                "username": username,
                "csrf": csrf,
                "expires": time.time() + self.ttl,
            }
        return token, csrf

    def get(self, token: str | None) -> dict | None:
        if not token:
            return None
        with self.lock:
            sess = self.data.get(token)
            if not sess:
                return None
            if sess["expires"] < time.time():
                self.data.pop(token, None)
                return None
            return dict(sess)

    def drop(self, token: str | None) -> None:
        if token:
            with self.lock:
                self.data.pop(token, None)


# ── приложение ───────────────────────────────────────────────────────

class Replicator:
    """Push/pull подписанных операций между мастерами."""

    def __init__(self, store, peers: list[dict], interval: int = 60):
        self.store = store
        self.peers = [p for p in peers if p.get("id") and p.get("url") and p.get("public_key")]
        self.interval = max(5, int(interval))
        self.stop_event = threading.Event()
        self.wake = threading.Event()
        self.last_pull: dict[str, int] = {p["id"]: 0 for p in self.peers}
        self.last_push: dict[str, int] = {p["id"]: 0 for p in self.peers}
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._loop, name="replicator", daemon=True)
        self.thread.start()

    def notify(self, _op=None) -> None:
        self.wake.set()

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            self.pull_all()
            self.push_all()
            self.wake.wait(self.interval)
            self.wake.clear()

    def _headers(self, method: str, path: str, query: str, body: bytes) -> dict:
        ts = str(int(time.time()))
        digest = hashlib.sha256(body).hexdigest()
        msg = f"{method}\n{path}\n{query}\n{digest}\n{ts}".encode()
        return {
            "X-Node-Id": self.store.node_id,
            "X-Node-Ts": ts,
            "X-Node-Sig": self.store._sign(msg),
            "Content-Type": "application/json",
        }

    def _call(self, peer: dict, method: str, path: str, query: str = "",
              body: bytes = b"") -> dict:
        url = peer["url"].rstrip("/") + path + (("?" + query) if query else "")
        req = urllib.request.Request(
            url, data=body if method == "POST" else None, method=method,
            headers=self._headers(method, path, query, body),
        )
        ctx = None
        if peer.get("insecure"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=10, context=ctx) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def push_all(self) -> None:
        for peer in self.peers:
            if peer["id"] == self.store.node_id:
                continue
            try:
                after = self.last_push.get(peer["id"], 0)
                while True:
                    ops = self.store.export_ops(after_hlc=after, limit=200)
                    if not ops:
                        break
                    body = json.dumps({"ops": ops}, ensure_ascii=False).encode()
                    self._call(peer, "POST", "/replicate/ops", body=body)
                    after = max(int(op["hlc"]) for op in ops)
                    self.last_push[peer["id"]] = after
                    if len(ops) < 200:
                        break
            except Exception as exc:
                print(f"replication push to {peer['id']} failed: {exc}", file=sys.stderr)

    def pull_all(self) -> None:
        for peer in self.peers:
            if peer["id"] == self.store.node_id:
                continue
            try:
                after = self.last_pull.get(peer["id"], 0)
                data = self._call(peer, "GET", "/replicate/ops", f"after_hlc={after}")
                ops = data.get("ops") or []
                if ops:
                    self.store.apply_ops(ops)
                    self.last_pull[peer["id"]] = max(int(op["hlc"]) for op in ops)
            except Exception as exc:
                print(f"replication pull from {peer['id']} failed: {exc}", file=sys.stderr)

    def stop(self) -> None:
        self.stop_event.set()
        self.wake.set()


class Panel:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        peers_cfg = list(cfg.get("peers", []) or [])
        peers_map = {p["id"]: p["public_key"] for p in peers_cfg
                     if p.get("id") and p.get("public_key")}
        self.store = Store(
            cfg["db_path"],
            cfg["cluster_key"],
            node_id=cfg.get("node_id", "master"),
            node_key_path=cfg.get("node_key"),
            peers=peers_map,
        )
        self.sessions = Sessions(int(cfg.get("session_ttl_hours", 12)))
        self.username = cfg.get("admin_username", "admin")
        self.password_hash = cfg.get("admin_password_hash", "")
        self.public_base = cfg.get("public_base_url", "").rstrip("/")
        self.rules_dir = cfg.get("rules_dir", "") or ""
        self.peers = peers_cfg
        self.node_public_key = self.store.node_public_key()
        self.replicator = Replicator(
            self.store, peers_cfg, interval=int(cfg.get("replication_interval", 60))
        )
        self.store.on_op = self.replicator.notify

    def verify_node_request(self, node_id: str, method: str, path: str, query: str,
                            body: bytes, ts: str, sig: str) -> bool:
        try:
            ts_int = int(ts)
        except (TypeError, ValueError):
            return False
        if abs(time.time() - ts_int) > 300:
            return False
        digest = hashlib.sha256(body).hexdigest()
        msg = f"{method}\n{path}\n{query}\n{digest}\n{ts}".encode()
        return self.store._verify(node_id, msg, sig)

    # ── subscription ──

    def subscription_payload(self, user: User) -> dict:
        secret = self.store.get_secret(user.uuid)
        token = self.store.subscription_token(user.uuid)
        sub_cfg = self.cfg.get("subscription", {}) or {}
        nodes = list(sub_cfg.get("nodes", []) or [])
        if user.visible_nodes:
            nodes = [n for n in nodes if n.get("id") in user.visible_nodes]
        url_to_node = {str(n.get("url")).rstrip("/"): n.get("id")
                       for n in (sub_cfg.get("nodes", []) or []) if n.get("url")}
        route_nodes: dict[str, set[str]] = {}
        route_exits: dict[str, str] = {}
        for route in self.store.list_routes():
            used: set[str] = set()
            exit_id = ""
            for hop in route.hops or []:
                for cand in hop.get("candidates", []) or []:
                    cand = str(cand)
                    nid = cand if cand in url_to_node.values() else url_to_node.get(cand.rstrip("/"), "")
                    if nid:
                        used.add(nid)
                        exit_id = nid
            route_nodes[route.name] = used
            route_exits[route.name] = exit_id
        for prof in sub_cfg.get("profiles", []) or []:
            for route in prof.get("routes", []) or []:
                name = route.get("name")
                if not name:
                    continue
                used: set[str] = set()
                exit_id = ""
                for hop in route.get("hops", []) or []:
                    for cand in hop.get("candidates", []) or []:
                        cand = str(cand)
                        nid = cand if cand in url_to_node.values() else url_to_node.get(cand.rstrip("/"), "")
                        if nid:
                            used.add(nid)
                            exit_id = nid
                route_nodes[str(name)] = used
                route_exits[str(name)] = exit_id

        all_node_ids = {n.get("id") for n in (sub_cfg.get("nodes", []) or []) if n.get("id")}
        allowed_nodes = set(user.visible_nodes) if user.visible_nodes else set(all_node_ids)
        if user.allowed_hops:
            allowed_nodes &= set(user.allowed_hops)
        allowed_exits = set(user.allowed_exits) if user.allowed_exits else set()

        visible_profiles = []
        for cp in self.store.list_client_profiles():
            if not cp.enabled:
                continue
            names = []
            if cp.split_enabled:
                names = [cp.route_ru, cp.route_non_ru, cp.route_private]
            used: set[str] = set()
            ok = True
            for name in names:
                name = (name or "").strip()
                if not name or name == "direct":
                    continue
                if name not in route_nodes:
                    ok = False
                    break
                used |= route_nodes[name]
                if allowed_exits and route_exits.get(name) not in allowed_exits:
                    ok = False
                    break
            if ok and used <= allowed_nodes:
                visible_profiles.append(cp.to_public())

        split = dict(sub_cfg.get("split_routing", {}) or {})
        rules = dict(split.get("rules", {}) or {})
        for key in ("geoip", "domains"):
            value = rules.get(key)
            if value and "://" not in str(value) and self.public_base:
                rules[key] = f"{self.public_base}/rules/{value}"
        split["rules"] = rules
        payload = {
            "version": 1,
            "user": {
                "uuid": user.uuid,
                "name": user.name,
                "secret": b64e(secret) if secret else "",
            },
            "subscription": {
                "url": f"{self.public_base}/sub/{token}" if self.public_base and token else "",
                "auto_update_hours": int(sub_cfg.get("auto_update_hours", 6)),
            },
            "nodes": nodes,
            "profiles": sub_cfg.get("profiles", []) or [],
            "routes": [r.to_public() for r in self.store.list_routes()],
            "client_profiles": visible_profiles,
            "split_routing": split,
        }
        return payload

    def sub_url(self, user: User) -> str:
        token = self.store.subscription_token(user.uuid)
        if not (self.public_base and token):
            return ""
        return f"{self.public_base}/sub/{token}"


# ── HTML ─────────────────────────────────────────────────────────────

CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b1020;color:#e8eefc;font:15px/1.45 system-ui,Segoe UI,Roboto,sans-serif}
a{color:#7db7ff}
.wrap{max-width:980px;margin:0 auto;padding:24px}
header{display:flex;align-items:center;gap:16px;margin-bottom:22px}
h1{font-size:22px;margin:0}
h2{font-size:17px;margin:24px 0 10px}
.card{background:#141a2e;border:1px solid #233052;border-radius:14px;padding:16px;margin:12px 0}
table{width:100%;border-collapse:collapse}
th,td{text-align:left;padding:9px 8px;border-bottom:1px solid #233052;vertical-align:top}
th{color:#93a4c8;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
input,textarea,select{width:100%;background:#0f1526;border:1px solid #2a3a60;color:#e8eefc;border-radius:9px;padding:9px 11px;font:inherit}
textarea{min-height:80px}
label{display:block;color:#93a4c8;font-size:12px;margin:10px 0 4px}
button,.btn{display:inline-block;background:#2563eb;color:#fff;border:0;border-radius:9px;padding:9px 14px;font:inherit;cursor:pointer;text-decoration:none}
button.secondary,.btn.secondary{background:#223154}
button.danger{background:#b42318}
button.warn{background:#a15c00}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.muted{color:#8b9bbd;font-size:13px}
.pill{display:inline-block;border-radius:99px;padding:2px 9px;font-size:12px;background:#1b2a4a;color:#9cc9ff}
.pill.ok{background:#103a2a;color:#5ee0a0}
.pill.off{background:#3a1616;color:#ff9b9b}
code,pre{background:#0f1526;border:1px solid #233052;border-radius:8px;padding:2px 6px;font-family:ui-monospace,Consolas,monospace;font-size:12px}
pre{padding:12px;overflow:auto;white-space:pre-wrap;word-break:break-all}
.error{color:#ff9b9b}
.nav a{margin-right:14px}
"""


def page(title: str, body: str, nav: str = "") -> bytes:
    html_doc = f"""<!DOCTYPE html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title><style>{CSS}</style></head>
<body><div class="wrap">
<header><h1>{html.escape(title)}</h1><div class="nav" style="margin-left:auto">{nav}</div></header>
{body}
</div></body></html>"""
    return html_doc.encode("utf-8")


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def fmt_ts(ms: int | None) -> str:
    if not ms:
        return "—"
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# ── HTTP handler ─────────────────────────────────────────────────────

class Handler(BaseHTTPRequestHandler):
    panel: Panel

    def log_message(self, fmt: str, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    # helpers

    def session_token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar = cookies.SimpleCookie(raw)
        morsel = jar.get("vpn_admin")
        return morsel.value if morsel else None

    def current(self) -> tuple[str | None, dict | None]:
        token = self.session_token()
        return token, self.panel.sessions.get(token)

    def redirect(self, location: str, cookie: str | None = None):
        self.send_response(302)
        self.send_header("Location", location)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def send_html(self, body: bytes, status: int = 200):
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_json(self, obj, status: int = 200):
        body = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def replication_get(self, parsed) -> None:
        if not self._check_node(parsed, "GET", b""):
            return
        qs = parse_qs(parsed.query)
        try:
            after = int(qs.get("after_hlc", ["0"])[0])
        except ValueError:
            after = 0
        self.send_json({"ops": self.panel.store.export_ops(after_hlc=after, limit=500)})

    def replication_post(self, parsed) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 20_000_000:
            return self.send_json({"error": "bad body"}, 400)
        body = self.rfile.read(length)
        if not self._check_node(parsed, "POST", body):
            return
        try:
            data = json.loads(body.decode("utf-8"))
            ops = data.get("ops") or []
            if not isinstance(ops, list):
                raise ValueError("ops must be list")
            result = self.panel.store.apply_ops(ops)
            self.send_json(result)
        except Exception as exc:
            self.send_json({"error": str(exc)}, 400)

    def _check_node(self, parsed, method: str, body: bytes) -> bool:
        node_id = self.headers.get("X-Node-Id", "")
        ts = self.headers.get("X-Node-Ts", "")
        sig = self.headers.get("X-Node-Sig", "")
        ok = self.panel.verify_node_request(
            node_id, method, parsed.path, parsed.query, body, ts, sig
        )
        if not ok:
            self.send_json({"error": "bad node signature"}, 403)
        return ok

    def read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1_000_000:
            return {}
        raw = self.rfile.read(length).decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw).items()}

    def require(self) -> tuple[str, dict] | None:
        token, sess = self.current()
        if not sess:
            self.redirect("/login")
            return None
        return token, sess

    def check_csrf(self, sess: dict, form: dict) -> bool:
        return hmac.compare_digest(str(form.get("csrf", "")), str(sess.get("csrf", "")))

    def nav(self, sess: dict | None) -> str:
        if not sess:
            return ""
        return ('<a href="/users">Пользователи</a>'
                '<a href="/profiles">Профили</a>'
                '<a href="/routes">Маршруты</a>'
                '<a href="/nodes">Узлы</a>'
                '<a href="/audit">Аудит</a>'
                '<a href="/logout">Выйти</a>')

    # routing

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/healthz":
                return self.send_json({"ok": True})
            if path == "/login":
                return self.login_page()
            if path == "/logout":
                token, _ = self.current()
                self.panel.sessions.drop(token)
                return self.redirect("/login", "vpn_admin=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict")
            if path.startswith("/sub/"):
                return self.public_subscription(path[len("/sub/"):])
            if path.startswith("/rules/"):
                return self.serve_rules(path[len("/rules/"):])
            if path in ("/replicate/ops", "/api/ops"):
                return self.replication_get(parsed)

            auth = self.require()
            if not auth:
                return
            token, sess = auth

            if path == "/":
                return self.redirect("/users")
            if path == "/users":
                return self.users_page(sess)
            if path == "/users/new":
                return self.user_form_page(sess)
            if path == "/nodes":
                return self.nodes_page(sess)
            if path == "/profiles":
                return self.profiles_page(sess)
            if path == "/routes":
                return self.routes_page(sess)
            m = re.fullmatch(r"/routes/([0-9a-fA-F-]{36})", path)
            if m:
                return self.route_edit_page(sess, m.group(1))
            m = re.fullmatch(r"/profiles/([0-9a-fA-F-]{36})", path)
            if m:
                return self.profile_edit_page(sess, m.group(1))
            if path == "/audit":
                return self.audit_page(sess)
            m = re.fullmatch(r"/users/([0-9a-fA-F-]{36})", path)
            if m:
                return self.user_page(sess, m.group(1))
            m = re.fullmatch(r"/users/([0-9a-fA-F-]{36})/sub\.json", path)
            if m:
                user = self.panel.store.get_user(m.group(1))
                if not user:
                    return self.send_json({"error": "not found"}, 404)
                return self.send_json(self.panel.subscription_payload(user))
            m = re.fullmatch(r"/users/([0-9a-fA-F-]{36})/sub\.png", path)
            if m:
                return self.qr_page(m.group(1))
            self.send_html(page("404", "<p>Не найдено</p>", self.nav(sess)), 404)
        except Exception as exc:  # не показываем детали наружу
            self.log_message("error: %s", exc)
            self.send_html(page("Ошибка", f"<p class='error'>{esc(exc)}</p>", ""), 500)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            if path == "/login":
                return self.do_login()
            if path in ("/replicate/ops", "/api/ops"):
                return self.replication_post(parsed)
            auth = self.require()
            if not auth:
                return
            token, sess = auth
            form = self.read_form()
            if not self.check_csrf(sess, form):
                return self.send_html(page("Ошибка", "<p class='error'>CSRF token mismatch</p>",
                                            self.nav(sess)), 403)

            if path == "/users/new":
                return self.create_user(form, sess)
            if path == "/profiles/new":
                return self.create_profile(form, sess)
            if path == "/routes/new":
                return self.create_route(form, sess)
            m = re.fullmatch(r"/routes/([0-9a-fA-F-]{36})/(save|delete)", path)
            if m:
                return self.route_action(m.group(1), m.group(2), form, sess)
            m = re.fullmatch(r"/profiles/([0-9a-fA-F-]{36})/(save|update|delete)", path)
            if m:
                return self.profile_action(m.group(1), m.group(2), form, sess)
            m = re.fullmatch(r"/users/([0-9a-fA-F-]{36})/(enable|disable|delete|rotate|revoke-sub)", path)
            if m:
                return self.user_action(m.group(1), m.group(2), sess)
            m = re.fullmatch(r"/users/([0-9a-fA-F-]{36})/devices/([0-9a-fA-F-]{36})/revoke", path)
            if m:
                self.panel.store.revoke_device(m.group(1), m.group(2), self.panel.username)
                return self.redirect(f"/users/{m.group(1)}")
            self.send_html(page("404", "<p>Не найдено</p>", self.nav(sess)), 404)
        except Exception as exc:
            self.log_message("error: %s", exc)
            self.send_html(page("Ошибка", f"<p class='error'>{esc(exc)}</p>", ""), 500)

    # login

    def login_page(self, error: str = ""):
        body = f"""
<div class="card" style="max-width:420px;margin:60px auto">
<form method="post" action="/login">
<label>Логин</label><input name="username" autocomplete="username" autofocus>
<label>Пароль</label><input name="password" type="password" autocomplete="current-password">
{('<p class="error">' + esc(error) + '</p>') if error else ''}
<div style="margin-top:16px"><button type="submit">Войти</button></div>
</form></div>"""
        self.send_html(page("Вход в панель", body))

    def do_login(self):
        form = self.read_form()
        username = form.get("username", "")
        password = form.get("password", "")
        if username != self.panel.username or not verify_password(password, self.panel.password_hash):
            time.sleep(0.4)
            return self.login_page("Неверный логин или пароль")
        token, csrf = self.panel.sessions.create(username)
        cookie = f"vpn_admin={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={self.panel.sessions.ttl}"
        self.redirect("/users", cookie)

    # pages

    def users_page(self, sess: dict):
        users = self.panel.store.list_users()
        rows = []
        for u in users:
            status = ("<span class='pill ok'>active</span>" if u.enabled
                      else "<span class='pill off'>disabled</span>")
            if u.expires_at and u.expires_at < int(time.time() * 1000):
                status = "<span class='pill off'>expired</span>"
            devices = len(self.panel.store.list_devices(u.uuid))
            rows.append(
                f"<tr><td><a href='/users/{esc(u.uuid)}'>{esc(u.name)}</a>"
                f"<div class='muted'>{esc(u.uuid)}</div></td>"
                f"<td>{status}</td><td>{devices}</td>"
                f"<td>{fmt_ts(u.created_at)}</td></tr>"
            )
        body = f"""
<div class="row" style="margin-bottom:12px">
<a class="btn" href="/users/new">+ Новый пользователь</a>
<span class="muted">Всего: {len(users)}</span>
</div>
<div class="card"><table>
<tr><th>Пользователь</th><th>Статус</th><th>Устройств</th><th>Создан</th></tr>
{''.join(rows) or '<tr><td colspan="4" class="muted">Пока нет пользователей</td></tr>'}
</table></div>
<p class="muted">Панель слушает только 127.0.0.1. Подключайтесь через SSH-туннель:
<code>ssh -L 8444:127.0.0.1:8444 root@SERVER</code></p>"""
        self.send_html(page("Пользователи", body, self.nav(sess)))

    def user_form_page(self, sess: dict):
        body = f"""
<div class="card"><form method="post" action="/users/new">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<label>Имя *</label><input name="name" required>
<label>Заметка</label><input name="note">
<label>Действует до (UTC, необязательно)</label><input name="expires" type="date">
<label>Лимит устройств (0 = без лимита)</label><input name="max_devices" type="number" min="0" value="0">
<label>Видимые узлы (через запятую, пусто = все)</label><input name="visible_nodes" placeholder="ru-1, de-1">
<label>Разрешённые hop-ы (пусто = все)</label><input name="allowed_hops" placeholder="ru-1, de-1">
<label>Разрешённые exit-ы (пусто = все)</label><input name="allowed_exits" placeholder="de-1">
<div style="margin-top:16px"><button type="submit">Создать</button>
<a class="btn secondary" href="/users">Отмена</a></div>
</form></div>"""
        self.send_html(page("Новый пользователь", body, self.nav(sess)))

    def create_user(self, form: dict, sess: dict):
        name = (form.get("name") or "").strip()
        if not name:
            return self.send_html(page("Ошибка", "<p class='error'>Имя обязательно</p>",
                                        self.nav(sess)), 400)
        expires_ms = None
        if form.get("expires"):
            try:
                dt = datetime.strptime(form["expires"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                expires_ms = int(dt.timestamp() * 1000) + 86_400_000 - 1
            except ValueError:
                pass
        split = lambda s: [x.strip() for x in (s or "").split(",") if x.strip()]
        user, _secret = self.panel.store.create_user(
            name=name,
            note=(form.get("note") or "").strip(),
            expires_at=expires_ms,
            max_devices=max(0, int(form.get("max_devices") or 0)),
            visible_nodes=split(form.get("visible_nodes", "")),
            allowed_hops=split(form.get("allowed_hops", "")),
            allowed_exits=split(form.get("allowed_exits", "")),
            actor=self.panel.username,
        )
        self.redirect(f"/users/{user.uuid}")

    def user_page(self, sess: dict, user_uuid: str):
        user = self.panel.store.get_user(user_uuid)
        if not user:
            return self.send_html(page("404", "<p>Пользователь не найден</p>",
                                        self.nav(sess)), 404)
        devices = self.panel.store.list_devices(user_uuid)
        sub_url = self.panel.sub_url(user)
        status = ("<span class='pill ok'>active</span>" if user.enabled
                  else "<span class='pill off'>disabled</span>")
        device_rows = "".join(
            f"<tr><td>{esc(d.device_id)}</td><td>{esc(d.name)}</td>"
            f"<td>{fmt_ts(d.last_seen_at)}</td><td>{esc(d.last_ip)}</td>"
            f"<td><form method='post' action='/users/{esc(user.uuid)}/devices/{esc(d.device_id)}/revoke' style='margin:0'>"
            f"<input type='hidden' name='csrf' value='{esc(sess['csrf'])}'>"
            f"<button class='danger' type='submit'>Отозвать</button></form></td></tr>"
            for d in devices
        ) or "<tr><td colspan='5' class='muted'>Устройства появятся после первого подключения</td></tr>"
        body = f"""
<div class="card">
<div class="row"><div style="flex:1"><h2 style="margin:0">{esc(user.name)}</h2>
<div class="muted">{esc(user.uuid)}</div></div><div>{status}</div></div>
<table style="margin-top:12px">
<tr><th>Создан</th><td>{fmt_ts(user.created_at)}</td></tr>
<tr><th>Действует до</th><td>{fmt_ts(user.expires_at) if user.expires_at else 'бессрочно'}</td></tr>
<tr><th>Лимит устройств</th><td>{user.max_devices or 'без лимита'}</td></tr>
<tr><th>Видимые узлы</th><td>{esc(', '.join(user.visible_nodes) or 'все')}</td></tr>
<tr><th>Разрешённые hop-ы</th><td>{esc(', '.join(user.allowed_hops) or 'все')}</td></tr>
<tr><th>Разрешённые exit-ы</th><td>{esc(', '.join(user.allowed_exits) or 'все')}</td></tr>
<tr><th>Заметка</th><td>{esc(user.note) or '—'}</td></tr>
</table>
</div>

<div class="card">
<h2 style="margin-top:0">Подписка</h2>
{f'<p><a href="{esc(sub_url)}">{esc(sub_url)}</a></p>' if sub_url else '<p class="muted">Задайте public_base_url в конфиге</p>'}
<pre>{esc(json.dumps(self.panel.subscription_payload(user), ensure_ascii=False, indent=2))}</pre>
<div class="row">
{f'<a class="btn" href="{esc(sub_url)}">Открыть JSON</a>' if sub_url else ''}
<a class="btn secondary" href="/users/{esc(user.uuid)}/sub.json">Скачать JSON</a>
<a class="btn secondary" href="/users/{esc(user.uuid)}/sub.png">QR</a>
</div>
<p class="muted">Ссылка-подписка является секретом. При отзыве она перестаёт работать.</p>
</div>

<div class="card">
<h2 style="margin-top:0">Действия</h2>
<div class="row">
<form method="post" action="/users/{esc(user.uuid)}/{'disable' if user.enabled else 'enable'}">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="{'warn' if user.enabled else ''}" type="submit">{'Отключить' if user.enabled else 'Включить'}</button></form>
<form method="post" action="/users/{esc(user.uuid)}/rotate">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="secondary" type="submit">Сменить секрет</button></form>
<form method="post" action="/users/{esc(user.uuid)}/revoke-sub">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="secondary" type="submit">Отозвать подписку</button></form>
<form method="post" action="/users/{esc(user.uuid)}/delete" onsubmit="return confirm('Удалить пользователя и все его данные?')">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="danger" type="submit">Удалить</button></form>
</div>
</div>

<div class="card">
<h2 style="margin-top:0">Устройства ({len(devices)})</h2>
<table><tr><th>ID</th><th>Имя</th><th>Последняя активность</th><th>IP</th><th></th></tr>
{device_rows}</table>
</div>"""
        self.send_html(page("Пользователь", body, self.nav(sess)))

    def user_action(self, user_uuid: str, action: str, sess: dict):
        store = self.panel.store
        if action == "enable":
            store.set_enabled(user_uuid, True, self.panel.username)
            return self.redirect(f"/users/{user_uuid}")
        if action == "disable":
            store.set_enabled(user_uuid, False, self.panel.username)
            return self.redirect(f"/users/{user_uuid}")
        if action == "delete":
            store.delete_user(user_uuid, self.panel.username)
            return self.redirect("/users")
        if action == "rotate":
            store.rotate_secret(user_uuid, self.panel.username)
            return self.redirect(f"/users/{user_uuid}")
        if action == "revoke-sub":
            store.revoke_subscription(user_uuid)
            return self.redirect(f"/users/{user_uuid}")
        return self.redirect("/users")

    def route_edit_page(self, sess: dict, route_id: str):
        r = self.panel.store.get_route(route_id)
        if not r:
            return self.send_html(page("404", "<p>Маршрут не найден</p>", self.nav(sess)), 404)
        nodes = (self.panel.cfg.get("subscription") or {}).get("nodes") or []
        node_options = "".join(
            f"<option value='{esc(n.get('id'))}'>{esc(n.get('id'))} — {esc(n.get('name'))}</option>"
            for n in nodes
        )
        hops = r.hops or []
        hop_rows = []
        for i, hop in enumerate(hops):
            cands = ", ".join(str(c) for c in (hop.get("candidates") or []))
            strategy = hop.get("strategy", "round")
            hop_rows.append(f"""
<div class="card" style="background:#0f1526">
<b>Hop {i + 1}</b>
<label>Кандидаты (node_id через запятую)</label>
<input name="hop_candidates_{i}" value="{esc(cands)}">
<label>Стратегия</label>
<select name="hop_strategy_{i}">
<option value="round" {'selected' if strategy == 'round' else ''}>round</option>
<option value="random" {'selected' if strategy == 'random' else ''}>random</option>
</select>
</div>""")
        body = f"""
<div class="card">
<form method="post" action="/routes/{esc(r.id)}/save" id="routeForm">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<input type="hidden" name="hops_count" value="{len(hops)}" id="hopsCount">
<label>Название маршрута</label><input name="name" value="{esc(r.name)}" required>
<label>Порядок</label><input name="sort_order" type="number" value="{r.sort_order}">
<h2>Цепочка (entry → … → exit)</h2>
{''.join(hop_rows)}
<div class="row" style="margin-top:10px">
<button type="button" class="secondary" onclick="addHop()">+ Добавить hop</button>
<button type="button" class="secondary" onclick="removeHop()">− Удалить последний</button>
</div>
<div class="row" style="margin-top:14px">
<button type="submit">Сохранить маршрут</button>
<a class="btn secondary" href="/routes">Назад</a>
</div>
</form>
<form method="post" action="/routes/{esc(r.id)}/delete" style="margin-top:14px"
 onsubmit="return confirm('Удалить маршрут?')">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="danger" type="submit">Удалить маршрут</button>
</form>
</div>
<script>
const NODES = {node_options!r};
function addHop() {{
  const n = document.getElementById('hopsCount');
  const i = parseInt(n.value, 10);
  const div = document.createElement('div');
  div.className = 'card';
  div.style.background = '#0f1526';
  div.innerHTML = '<b>Hop ' + (i + 1) + '</b>' +
    '<label>Кандидаты (node_id через запятую)</label>' +
    '<input name="hop_candidates_' + i + '" value="">' +
    '<label>Стратегия</label>' +
    '<select name="hop_strategy_' + i + '"><option value="round">round</option>' +
    '<option value="random">random</option></select>';
  document.getElementById('routeForm').insertBefore(div, document.getElementById('routeForm').lastElementChild);
  n.value = i + 1;
}}
function removeHop() {{
  const n = document.getElementById('hopsCount');
  const i = parseInt(n.value, 10);
  if (i <= 1) return;
  const inputs = document.querySelectorAll('[name^=hop_candidates_]');
  const sels = document.querySelectorAll('[name^=hop_strategy_]');
  const lastInput = inputs[inputs.length - 1];
  const lastSel = sels[sels.length - 1];
  lastInput.closest('.card').remove();
  n.value = i - 1;
}}
</script>"""
        self.send_html(page("Маршрут: " + r.name, body, self.nav(sess)))

    def create_route(self, form: dict, sess: dict):
        name = (form.get("name") or "").strip()
        if not name:
            return self.send_html(page("Ошибка", "<p class='error'>Название обязательно</p>",
                                        self.nav(sess)), 400)
        hops = []
        try:
            count = int(form.get("hops_count") or 1)
        except ValueError:
            count = 1
        for i in range(max(1, min(count, 3))):
            cands = [c.strip() for c in (form.get(f"hop_candidates_{i}") or "").split(",")
                     if c.strip()]
            if not cands:
                continue
            hops.append({"candidates": cands,
                         "strategy": form.get(f"hop_strategy_{i}") or "round"})
        if not hops:
            return self.send_html(page("Ошибка", "<p class='error'>Нужен хотя бы один hop</p>",
                                        self.nav(sess)), 400)
        self.panel.store.create_route(name, hops, actor=self.panel.username)
        self.redirect("/routes")

    def route_action(self, route_id: str, action: str, form: dict, sess: dict):
        if action == "delete":
            self.panel.store.delete_route(route_id, self.panel.username)
        else:
            hops = []
            try:
                count = int(form.get("hops_count") or 1)
            except ValueError:
                count = 1
            for i in range(max(1, min(count, 3))):
                cands = [c.strip() for c in (form.get(f"hop_candidates_{i}") or "").split(",")
                         if c.strip()]
                if cands:
                    hops.append({"candidates": cands,
                                 "strategy": form.get(f"hop_strategy_{i}") or "round"})
            sort_order = None
            if form.get("sort_order"):
                try:
                    sort_order = int(form["sort_order"])
                except ValueError:
                    pass
            self.panel.store.update_route(
                route_id,
                name=(form.get("name") or "").strip() or None,
                hops=hops or None,
                sort_order=sort_order,
            )
        self.redirect("/routes")

    def routes_page(self, sess: dict):
        routes = self.panel.store.list_routes()
        rows = []
        for r in routes:
            chain = " → ".join(
                "/".join(str(c) for c in (h.get("candidates") or [])) for h in (r.hops or [])
            )
            rows.append(f"""
<tr><td><b>{esc(r.name)}</b><div class="muted">{esc(r.id)}</div></td>
<td><code>{esc(chain)}</code></td><td>{len(r.hops or [])}</td>
<td><a class="btn secondary" href="/routes/{esc(r.id)}">Изменить</a></td></tr>""")
        body = f"""
<div class="card">
<h2 style="margin-top:0">Новый маршрут</h2>
<form method="post" action="/routes/new">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<input type="hidden" name="hops_count" value="1">
<label>Название</label><input name="name" required>
<label>Hop 1 — кандидаты (node_id через запятую)</label><input name="hop_candidates_0" placeholder="ru-1">
<label>Стратегия</label><select name="hop_strategy_0"><option>round</option><option>random</option></select>
<div style="margin-top:12px"><button type="submit">Создать маршрут</button></div>
</form>
</div>
<div class="card">
<h2 style="margin-top:0">Маршруты</h2>
<table><tr><th>Название</th><th>Цепочка</th><th>Hop-ов</th><th></th></tr>
{''.join(rows) or '<tr><td colspan="4" class="muted">Маршрутов пока нет</td></tr>'}
</table>
</div>"""
        self.send_html(page("Маршруты", body, self.nav(sess)))

    def profiles_page(self, sess: dict):
        profiles = self.panel.store.list_client_profiles()
        routes = [r.name for r in self.panel.store.list_routes()]
        route_options = "".join(f"<option value='{esc(r)}'>{esc(r)}</option>" for r in routes)
        rows = []
        for p in profiles:
            rows.append(f"""
<tr>
<td><b>{esc(p.name)}</b><div class="muted">{esc(p.id)}</div></td>
<td>{esc(p.mode)}</td>
<td>{'ON' if p.split_enabled else 'off'}</td>
<td>{esc(p.route_ru) or '—'} / {esc(p.route_non_ru) or '—'} / {esc(p.route_private) or 'direct'}</td>
<td><a class="btn secondary" href="/profiles/{esc(p.id)}">Изменить</a></td>
</tr>""")
        body = f"""
<div class="card">
<h2 style="margin-top:0">Новый профиль</h2>
<form method="post" action="/profiles/new">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<div class="row">
<div style="flex:1"><label>Название</label><input name="name" required></div>
<div><label>Режим</label>
<select name="mode"><option value="proxy">proxy</option><option value="vpn">vpn</option></select></div>
</div>
<div class="row">
<div style="flex:1"><label>RU маршрут</label><select name="route_ru"><option value="">—</option>{route_options}</select></div>
<div style="flex:1"><label>non-RU маршрут</label><select name="route_non_ru"><option value="">—</option>{route_options}</select></div>
<div style="flex:1"><label>Private</label><select name="route_private"><option value="direct">direct</option>{route_options}</select></div>
</div>
<label><input type="checkbox" name="split_enabled" value="1" style="width:auto"> Split routing</label>
<div style="margin-top:12px"><button type="submit">Создать профиль</button></div>
</form>
<p class="muted">Маршруты создаются в разделе <a href="/routes">Маршруты</a>.</p>
</div>
<div class="card">
<h2 style="margin-top:0">Профили подписки</h2>
<table><tr><th>Профиль</th><th>Режим</th><th>Split</th><th>RU / non-RU / private</th><th></th></tr>
{''.join(rows) or '<tr><td colspan="5" class="muted">Профилей пока нет</td></tr>'}
</table>
<p class="muted">Все активные профили попадают в подписку и создаются в приложении отдельными профилями.</p>
</div>"""
        self.send_html(page("Профили", body, self.nav(sess)))

    def profile_edit_page(self, sess: dict, profile_id: str):
        p = self.panel.store.get_client_profile(profile_id)
        if not p:
            return self.send_html(page("404", "<p>Профиль не найден</p>", self.nav(sess)), 404)
        routes = [r.name for r in self.panel.store.list_routes()]
        def opts(current: str) -> str:
            out = "<option value=''>—</option>"
            if current and current not in routes:
                out += f"<option value='{esc(current)}' selected>{esc(current)} (нет в конструкторе)</option>"
            for r in routes:
                sel = " selected" if r == current else ""
                out += f"<option value='{esc(r)}'{sel}>{esc(r)}</option>"
            return out
        body = f"""
<div class="card">
<form method="post" action="/profiles/{esc(p.id)}/save">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<label>Название</label><input name="name" value="{esc(p.name)}" required>
<label>Режим</label>
<select name="mode">
<option value="proxy" {'selected' if p.mode == 'proxy' else ''}>proxy</option>
<option value="vpn" {'selected' if p.mode == 'vpn' else ''}>vpn</option>
</select>
<label><input type="checkbox" name="split_enabled" value="1" style="width:auto"
 {'checked' if p.split_enabled else ''}> Split routing</label>
<div class="row">
<div style="flex:1"><label>RU маршрут</label><select name="route_ru">{opts(p.route_ru)}</select></div>
<div style="flex:1"><label>non-RU маршрут</label><select name="route_non_ru">{opts(p.route_non_ru)}</select></div>
<div style="flex:1"><label>Private</label><select name="route_private">{opts(p.route_private)}</select></div>
</div>
<label>Порядок</label><input name="sort_order" type="number" value="{p.sort_order}">
<div class="row" style="margin-top:14px">
<button type="submit">Сохранить</button>
<a class="btn secondary" href="/profiles">Назад</a>
<a class="btn secondary" href="/routes">Маршруты</a>
</div>
</form>
<form method="post" action="/profiles/{esc(p.id)}/delete" style="margin-top:14px"
 onsubmit="return confirm('Удалить профиль?')">
<input type="hidden" name="csrf" value="{esc(sess['csrf'])}">
<button class="danger" type="submit">Удалить профиль</button>
</form>
</div>"""
        self.send_html(page("Профиль: " + p.name, body, self.nav(sess)))

    def create_profile(self, form: dict, sess: dict):
        name = (form.get("name") or "").strip()
        if not name:
            return self.send_html(page("Ошибка", "<p class='error'>Название обязательно</p>",
                                        self.nav(sess)), 400)
        self.panel.store.create_client_profile(
            name=name,
            mode=(form.get("mode") or "proxy").strip(),
            split_enabled=form.get("split_enabled") == "1",
            route_ru=(form.get("route_ru") or "").strip(),
            route_non_ru=(form.get("route_non_ru") or "").strip(),
            route_private=(form.get("route_private") or "direct").strip() or "direct",
            actor=self.panel.username,
        )
        self.redirect("/profiles")

    def profile_action(self, profile_id: str, action: str, form: dict, sess: dict):
        store = self.panel.store
        if action == "delete":
            store.delete_client_profile(profile_id, self.panel.username)
        else:
            profile = store.get_client_profile(profile_id)
            if profile:
                updates = {
                    "name": (form.get("name") or profile.name).strip(),
                    "mode": (form.get("mode") or profile.mode).strip(),
                    "split_enabled": form.get("split_enabled") == "1",
                    "route_ru": (form.get("route_ru") or "").strip(),
                    "route_non_ru": (form.get("route_non_ru") or "").strip(),
                    "route_private": (form.get("route_private") or "direct").strip() or "direct",
                }
                if form.get("sort_order"):
                    try:
                        updates["sort_order"] = int(form["sort_order"])
                    except ValueError:
                        pass
                if action == "update" and "enabled" in form:
                    updates["enabled"] = form.get("enabled") == "1"
                store.update_client_profile(profile_id, **updates)
        self.redirect("/profiles")

    def nodes_page(self, sess: dict):
        sub = self.panel.cfg.get("subscription") or {}
        nodes = sub.get("nodes") or []
        node_rows = "".join(
            f"<tr><td>{esc(n.get('id'))}</td><td>{esc(n.get('name'))}</td>"
            f"<td>{esc(n.get('region'))}</td><td><code>{esc(n.get('url'))}</code></td></tr>"
            for n in nodes
        ) or "<tr><td colspan='4' class='muted'>Нет узлов в subscription.nodes</td></tr>"
        peer_rows = "".join(
            f"<tr><td>{esc(p.get('id'))}</td><td><code>{esc(p.get('url'))}</code></td>"
            f"<td><code>{esc((p.get('public_key') or '')[:16])}…</code></td></tr>"
            for p in self.panel.peers
        ) or "<tr><td colspan='3' class='muted'>Пиры не настроены</td></tr>"
        rules_rows = ""
        if self.panel.rules_dir and os.path.isdir(self.panel.rules_dir):
            for name in sorted(os.listdir(self.panel.rules_dir)):
                path = os.path.join(self.panel.rules_dir, name)
                if os.path.isfile(path):
                    rules_rows += (f"<tr><td>{esc(name)}</td><td>{os.path.getsize(path)} B</td>"
                                   f"<td>{fmt_ts(int(os.path.getmtime(path) * 1000))}</td></tr>")
        rules_rows = rules_rows or "<tr><td colspan='3' class='muted'>Нет файлов правил</td></tr>"
        body = f"""
<div class="card">
<h2 style="margin-top:0">Этот узел</h2>
<table>
<tr><th>node_id</th><td><code>{esc(self.panel.store.node_id)}</code></td></tr>
<tr><th>public_key</th><td><code>{esc(self.panel.node_public_key)}</code></td></tr>
<tr><th>cluster key</th><td><code>{esc(getattr(self.panel.store, 'cluster_key_path', ''))}</code></td></tr>
</table>
</div>
<div class="card">
<h2 style="margin-top:0">Узлы (subscription.nodes)</h2>
<table><tr><th>ID</th><th>Имя</th><th>Регион</th><th>URL</th></tr>{node_rows}</table>
</div>
<div class="card">
<h2 style="margin-top:0">Пиры репликации</h2>
<table><tr><th>ID</th><th>URL</th><th>Public key</th></tr>{peer_rows}</table>
</div>
<div class="card">
<h2 style="margin-top:0">Правила split-routing</h2>
<table><tr><th>Файл</th><th>Размер</th><th>Изменён</th></tr>{rules_rows}</table>
<p class="muted">Обновление: <code>python -m admin.rules --config admin/config.yaml --update</code></p>
</div>"""
        self.send_html(page("Узлы", body, self.nav(sess)))

    def audit_page(self, sess: dict):
        rows = "".join(
            f"<tr><td>{fmt_ts(r['ts'])}</td><td>{esc(r['actor'])}</td>"
            f"<td>{esc(r['action'])}</td><td>{esc(r['target'])}</td>"
            f"<td>{esc(r['details'])}</td></tr>"
            for r in self.panel.store.recent_audit()
        )
        body = f"<div class='card'><table><tr><th>Время</th><th>Кто</th><th>Действие</th><th>Объект</th><th>Детали</th></tr>{rows}</table></div>"
        self.send_html(page("Аудит", body, self.nav(sess)))

    # public subscription

    def public_subscription(self, token: str):
        user = self.panel.store.get_user_by_token(token)
        if not user:
            return self.send_json({"error": "not found"}, 404)
        if not user.enabled:
            return self.send_json({"error": "disabled"}, 403)
        if user.expires_at and user.expires_at < int(time.time() * 1000):
            return self.send_json({"error": "expired"}, 403)
        self.send_json(self.panel.subscription_payload(user))

    def serve_rules(self, name: str):
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", name or ""):
            return self.send_json({"error": "bad name"}, 400)
        if not self.panel.rules_dir:
            return self.send_json({"error": "rules disabled"}, 404)
        path = os.path.join(self.panel.rules_dir, os.path.basename(name))
        try:
            with open(path, "rb") as f:
                data = f.read()
        except OSError:
            return self.send_json({"error": "not found"}, 404)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "public, max-age=3600")
        self.end_headers()
        self.wfile.write(data)

    def qr_page(self, user_uuid: str):
        user = self.panel.store.get_user(user_uuid)
        if not user:
            return self.send_html(page("404", "<p>Не найдено</p>", ""), 404)
        payload = json.dumps(self.panel.subscription_payload(user), ensure_ascii=False)
        try:
            import qrcode
        except ImportError:
            return self.send_html(page("QR", "<p class='error'>Установите qrcode: pip install qrcode[pil]</p>",
                                        ""), 503)
        img = qrcode.make(payload)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        data = buf.getvalue()
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


# ── entry point ──────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def main() -> None:
    parser = argparse.ArgumentParser(description="VPN admin panel")
    parser.add_argument("--config", default="admin/config.yaml")
    parser.add_argument("--hash-password", metavar="PASSWORD",
                        help="напечатать hash для config.yaml и выйти")
    parser.add_argument("--show-node-key", action="store_true",
                        help="напечатать node_id и публичный ключ узла")
    args = parser.parse_args()

    if args.hash_password:
        print(hash_password(args.hash_password))
        return

    cfg = load_config(args.config)

    if args.show_node_key:
        peers_map = {
            p["id"]: p["public_key"] for p in (cfg.get("peers") or [])
            if p.get("id") and p.get("public_key")
        }
        store = Store(
            cfg["db_path"], cfg["cluster_key"],
            node_id=cfg.get("node_id", "master"),
            node_key_path=cfg.get("node_key"),
            peers=peers_map,
        )
        print(f"node_id: {store.node_id}")
        print(f"public_key: {store.node_public_key()}")
        store.close()
        return

    panel = Panel(cfg)
    Handler.panel = panel
    host = cfg.get("listen_host", "127.0.0.1")
    port = int(cfg.get("listen_port", 8444))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Admin panel: http://{host}:{port}  (SSH tunnel only)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
