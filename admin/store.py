"""SQLite-хранилище пользователей, устройств и подписок.

Секреты пользователей шифруются cluster-ключом (AES-256-GCM).
Панель и VPN-сервер используют один и тот же файл БД.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import uuid as uuidlib
from dataclasses import dataclass
from typing import Any, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def now_ms() -> int:
    return int(time.time() * 1000)


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64d(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def json_text(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def json_load(text: str, default: Any) -> Any:
    try:
        return json.loads(text)
    except Exception:
        return default


@dataclass
class User:
    uuid: str
    name: str
    note: str
    enabled: bool
    expires_at: Optional[int]
    max_devices: int
    visible_nodes: list[str]
    allowed_hops: list[str]
    allowed_exits: list[str]
    created_at: int
    updated_at: int
    updated_by: str
    deleted: bool

    def to_public(self) -> dict:
        return {
            "uuid": self.uuid,
            "name": self.name,
            "note": self.note,
            "enabled": self.enabled,
            "expires_at": self.expires_at,
            "max_devices": self.max_devices,
            "visible_nodes": self.visible_nodes,
            "allowed_hops": self.allowed_hops,
            "allowed_exits": self.allowed_exits,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "deleted": self.deleted,
        }


@dataclass
class Device:
    device_id: str
    user_uuid: str
    name: str
    enabled: bool
    created_at: int
    updated_at: int
    last_seen_at: Optional[int]
    last_ip: str


@dataclass
class ClientProfile:
    id: str
    name: str
    mode: str
    enabled: bool
    split_enabled: bool
    route_ru: str
    route_non_ru: str
    route_private: str
    sort_order: int
    created_at: int
    updated_at: int
    updated_by: str

    def to_public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "mode": self.mode,
            "enabled": self.enabled,
            "split_enabled": self.split_enabled,
            "route_ru": self.route_ru,
            "route_non_ru": self.route_non_ru,
            "route_private": self.route_private,
            "sort_order": self.sort_order,
        }


@dataclass
class Route:
    id: str
    name: str
    hops: list
    sort_order: int
    created_at: int
    updated_at: int
    updated_by: str

    def to_public(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hops": self.hops,
            "sort_order": self.sort_order,
        }


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    uuid TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    expires_at INTEGER,
    max_devices INTEGER NOT NULL DEFAULT 0,
    visible_nodes TEXT NOT NULL DEFAULT '[]',
    allowed_hops TEXT NOT NULL DEFAULT '[]',
    allowed_exits TEXT NOT NULL DEFAULT '[]',
    secret_enc TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    user_uuid TEXT NOT NULL REFERENCES users(uuid) ON DELETE CASCADE,
    name TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    last_seen_at INTEGER,
    last_ip TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_devices_user ON devices(user_uuid);

CREATE TABLE IF NOT EXISTS subscriptions (
    user_uuid TEXT PRIMARY KEY REFERENCES users(uuid) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL,
    revoked_at INTEGER
);

CREATE TABLE IF NOT EXISTS client_profiles (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'proxy',
    enabled INTEGER NOT NULL DEFAULT 1,
    split_enabled INTEGER NOT NULL DEFAULT 0,
    route_ru TEXT NOT NULL DEFAULT '',
    route_non_ru TEXT NOT NULL DEFAULT '',
    route_private TEXT NOT NULL DEFAULT 'direct',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routes (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    hops TEXT NOT NULL DEFAULT '[]',
    sort_order INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tombstones (
    uuid TEXT PRIMARY KEY,
    deleted_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS oplog (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    op_id TEXT NOT NULL UNIQUE,
    origin TEXT NOT NULL,
    entity TEXT NOT NULL,
    entity_key TEXT NOT NULL,
    op TEXT NOT NULL,
    payload TEXT NOT NULL,
    hlc INTEGER NOT NULL,
    signature TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS applied_ops (
    op_id TEXT PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL DEFAULT '',
    details TEXT NOT NULL DEFAULT ''
);
"""


class Store:
    def __init__(self, db_path: str, cluster_key_path: str, node_id: str = "master",
                 node_key_path: Optional[str] = None,
                 peers: Optional[dict[str, str]] = None):
        self.db_path = db_path
        self.cluster_key_path = cluster_key_path
        self.node_id = node_id
        self.node_key_path = node_key_path or os.path.join(
            os.path.dirname(os.path.abspath(cluster_key_path)), "node.key"
        )
        # peers: node_id -> Ed25519 public key (base64url, raw)
        self.peers = dict(peers or {})
        self.on_op = None
        self.lock = threading.RLock()
        parent = os.path.dirname(os.path.abspath(db_path))
        os.makedirs(parent, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False,
                                    isolation_level=None)
        # isolation_level=None — autocommit. Иначе SELECT открывает
        # долгоживущую read-транзакцию: vpn-server перестаёт видеть
        # пользователей, созданных после старта, и получает
        # "database is locked" на записи.
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA busy_timeout=5000")
        with self.lock:
            self.conn.executescript(SCHEMA)
            self._migrate()
            self.conn.commit()
        self.cluster_key = self._load_or_create_key()
        self.private_key = self._load_or_create_node_key()
        self._last_hlc = int(self._meta_get("last_hlc", "0"))

    def _migrate(self) -> None:
        cols = [r["name"] for r in self.conn.execute("PRAGMA table_info(oplog)").fetchall()]
        if "signature" not in cols:
            self.conn.execute("ALTER TABLE oplog ADD COLUMN signature TEXT NOT NULL DEFAULT ''")

    # ── cluster key / crypto ─────────────────────────────────────────

    def _load_or_create_key(self) -> bytes:
        try:
            with open(self.cluster_key_path, "rb") as f:
                key = f.read()
            if len(key) == 32:
                return key
        except FileNotFoundError:
            pass
        os.makedirs(os.path.dirname(os.path.abspath(self.cluster_key_path)), exist_ok=True)
        key = os.urandom(32)
        with open(self.cluster_key_path, "wb") as f:
            f.write(key)
        try:
            os.chmod(self.cluster_key_path, 0o600)
        except OSError:
            pass
        return key

    def _load_or_create_node_key(self) -> Ed25519PrivateKey:
        try:
            with open(self.node_key_path, "rb") as f:
                return serialization.load_pem_private_key(f.read(), password=None)
        except FileNotFoundError:
            pass
        os.makedirs(os.path.dirname(os.path.abspath(self.node_key_path)), exist_ok=True)
        key = Ed25519PrivateKey.generate()
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with open(self.node_key_path, "wb") as f:
            f.write(pem)
        try:
            os.chmod(self.node_key_path, 0o600)
        except OSError:
            pass
        return key

    def node_public_key(self) -> str:
        raw = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return b64e(raw)

    def _sign(self, data: bytes) -> str:
        return b64e(self.private_key.sign(data))

    def _verify(self, origin: str, data: bytes, signature: str) -> bool:
        pub = self.peers.get(origin)
        if not pub:
            return False
        try:
            key = Ed25519PublicKey.from_public_bytes(b64d(pub))
            key.verify(b64d(signature), data)
            return True
        except Exception:
            return False

    @staticmethod
    def _canonical_op(op: dict) -> bytes:
        body = {k: op.get(k) for k in
                ("op_id", "origin", "entity", "entity_key", "op", "payload", "hlc")}
        return json.dumps(body, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode("utf-8")

    def _encrypt_secret(self, user_uuid: str, secret: bytes) -> str:
        nonce = os.urandom(12)
        ct = AESGCM(self.cluster_key).encrypt(nonce, secret, user_uuid.encode())
        return b64e(nonce + ct)

    def _decrypt_secret(self, user_uuid: str, blob: str) -> bytes:
        raw = b64d(blob)
        return AESGCM(self.cluster_key).decrypt(raw[:12], raw[12:], user_uuid.encode())

    def get_secret(self, user_uuid: str) -> Optional[bytes]:
        with self.lock:
            row = self.conn.execute(
                "SELECT secret_enc FROM users WHERE uuid=? AND deleted=0", (user_uuid,)
            ).fetchone()
        if not row:
            return None
        return self._decrypt_secret(user_uuid, row["secret_enc"])

    # ── meta / HLC ───────────────────────────────────────────────────

    def _meta_get(self, key: str, default: str) -> str:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def _meta_set(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta(key,value) VALUES(?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def next_hlc(self) -> int:
        with self.lock:
            hlc = max(now_ms(), self._last_hlc + 1)
            self._last_hlc = hlc
            self._meta_set("last_hlc", str(hlc))
            self.conn.commit()
            return hlc

    # ── audit / oplog ────────────────────────────────────────────────

    def audit(self, actor: str, action: str, target: str = "", details: str = "") -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO audit_log(ts,actor,action,target,details) VALUES(?,?,?,?,?)",
                (now_ms(), actor, action, target, details),
            )
            self.conn.commit()

    def _user_payload(self, user_uuid: str) -> dict:
        with self.lock:
            row = self.conn.execute("SELECT * FROM users WHERE uuid=?", (user_uuid,)).fetchone()
        return dict(row) if row else {}

    def _device_payload(self, device_id: str) -> dict:
        with self.lock:
            row = self.conn.execute("SELECT * FROM devices WHERE device_id=?", (device_id,)).fetchone()
        return dict(row) if row else {}

    def _subscription_payload(self, user_uuid: str) -> dict:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM subscriptions WHERE user_uuid=?", (user_uuid,)
            ).fetchone()
        return dict(row) if row else {}

    def _log_op(self, entity: str, entity_key: str, op: str, payload: dict) -> dict:
        with self.lock:
            hlc = self.next_hlc()
            body = {
                "op_id": str(uuidlib.uuid4()),
                "origin": self.node_id,
                "entity": entity,
                "entity_key": entity_key,
                "op": op,
                "payload": payload,
                "hlc": hlc,
            }
            signature = self._sign(self._canonical_op(body))
            self.conn.execute(
                "INSERT INTO oplog(op_id,origin,entity,entity_key,op,payload,hlc,signature) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (body["op_id"], body["origin"], entity, entity_key, op,
                 json_text(payload), hlc, signature),
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO applied_ops(op_id,applied_at) VALUES(?,?)",
                (body["op_id"], now_ms()),
            )
            self.conn.commit()
        record = dict(body, signature=signature)
        callback = self.on_op
        if callback:
            try:
                callback(record)
            except Exception:
                pass
        return record

    # ── replication: export/apply ────────────────────────────────────

    def export_ops(self, after_hlc: int = 0, limit: int = 500) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM oplog WHERE hlc > ? ORDER BY hlc, seq LIMIT ?",
                (after_hlc, limit),
            ).fetchall()
        return [
            {
                "op_id": r["op_id"],
                "origin": r["origin"],
                "entity": r["entity"],
                "entity_key": r["entity_key"],
                "op": r["op"],
                "payload": json_load(r["payload"], {}),
                "hlc": r["hlc"],
                "signature": r["signature"],
            }
            for r in rows
        ]

    def apply_ops(self, ops: list[dict]) -> dict:
        applied = skipped = errors = 0
        for op in ops:
            try:
                result = self.apply_op(op)
                if result == "applied":
                    applied += 1
                else:
                    skipped += 1
            except Exception:
                errors += 1
        return {"applied": applied, "skipped": skipped, "errors": errors}

    def apply_op(self, op: dict) -> str:
        op_id = str(op.get("op_id") or "")
        origin = str(op.get("origin") or "")
        entity = str(op.get("entity") or "")
        entity_key = str(op.get("entity_key") or "")
        kind = str(op.get("op") or "")
        hlc = int(op.get("hlc") or 0)
        payload = op.get("payload") or {}
        signature = str(op.get("signature") or "")
        if not (op_id and origin and entity and entity_key and kind and hlc and signature):
            raise ValueError("incomplete op")
        if origin != self.node_id and not self._verify(origin, self._canonical_op(op), signature):
            raise ValueError("bad signature")
        with self.lock:
            if self.conn.execute("SELECT 1 FROM applied_ops WHERE op_id=?", (op_id,)).fetchone():
                return "skipped"
            if entity == "user":
                if kind == "delete":
                    self.conn.execute("DELETE FROM users WHERE uuid=?", (entity_key,))
                    self.conn.execute(
                        "INSERT OR REPLACE INTO tombstones(uuid,deleted_at) VALUES(?,?)",
                        (entity_key, hlc),
                    )
                elif kind == "upsert":
                    tomb = self.conn.execute(
                        "SELECT deleted_at FROM tombstones WHERE uuid=?", (entity_key,)
                    ).fetchone()
                    if tomb and tomb["deleted_at"] >= hlc:
                        self._record_applied(op_id)
                        self.conn.commit()
                        return "skipped"
                    existing = self.conn.execute(
                        "SELECT updated_at FROM users WHERE uuid=?", (entity_key,)
                    ).fetchone()
                    incoming_ts = int(payload.get("updated_at") or hlc)
                    if existing and existing["updated_at"] > incoming_ts:
                        self._record_applied(op_id)
                        self.conn.commit()
                        return "skipped"
                    self._upsert_user(payload, entity_key)
                else:
                    raise ValueError("bad user op")
            elif entity == "device":
                if kind == "delete":
                    self.conn.execute("DELETE FROM devices WHERE device_id=?", (entity_key,))
                elif kind == "upsert":
                    self._upsert_device(payload, entity_key)
                else:
                    raise ValueError("bad device op")
            elif entity == "subscription":
                if kind in ("upsert", "delete"):
                    if kind == "delete":
                        self.conn.execute("DELETE FROM subscriptions WHERE user_uuid=?", (entity_key,))
                    else:
                        self._upsert_subscription(payload, entity_key)
                else:
                    raise ValueError("bad subscription op")
            elif entity == "profile":
                if kind == "delete":
                    self.conn.execute("DELETE FROM client_profiles WHERE id=?", (entity_key,))
                elif kind == "upsert":
                    self._upsert_client_profile(payload, entity_key)
                else:
                    raise ValueError("bad profile op")
            elif entity == "route":
                if kind == "delete":
                    self.conn.execute("DELETE FROM routes WHERE id=?", (entity_key,))
                elif kind == "upsert":
                    self._upsert_route(payload, entity_key)
                else:
                    raise ValueError("bad route op")
            else:
                raise ValueError("unknown entity")
            self._record_applied(op_id)
            if hlc > self._last_hlc:
                self._last_hlc = hlc
                self._meta_set("last_hlc", str(hlc))
            self.conn.commit()
        return "applied"

    def _record_applied(self, op_id: str) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO applied_ops(op_id,applied_at) VALUES(?,?)",
            (op_id, now_ms()),
        )

    def _upsert_user(self, payload: dict, user_uuid: str) -> None:
        cols = ("uuid", "name", "note", "enabled", "expires_at", "max_devices",
                "visible_nodes", "allowed_hops", "allowed_exits", "secret_enc",
                "created_at", "updated_at", "updated_by", "deleted")
        values = []
        for col in cols:
            value = payload.get(col)
            if col == "uuid":
                value = user_uuid
            elif col in ("visible_nodes", "allowed_hops", "allowed_exits"):
                value = value if isinstance(value, str) else json_text(value or [])
            elif col == "enabled":
                value = 1 if value else 0
            elif col == "deleted":
                value = 1 if value else 0
            values.append(value)
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "uuid")
        self.conn.execute(
            f"INSERT INTO users({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(uuid) DO UPDATE SET {updates}",
            values,
        )

    def _upsert_device(self, payload: dict, device_id: str) -> None:
        if not self.conn.execute("SELECT 1 FROM users WHERE uuid=?", (payload.get("user_uuid"),)).fetchone():
            return
        cols = ("device_id", "user_uuid", "name", "enabled", "created_at", "updated_at",
                "last_seen_at", "last_ip")
        values = []
        for col in cols:
            value = payload.get(col)
            if col == "device_id":
                value = device_id
            elif col == "enabled":
                value = 1 if value else 0
            values.append(value)
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "device_id")
        self.conn.execute(
            f"INSERT INTO devices({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(device_id) DO UPDATE SET {updates}",
            values,
        )

    def _upsert_subscription(self, payload: dict, user_uuid: str) -> None:
        if not self.conn.execute("SELECT 1 FROM users WHERE uuid=?", (user_uuid,)).fetchone():
            return
        self.conn.execute(
            "INSERT INTO subscriptions(user_uuid,token,created_at,revoked_at) VALUES(?,?,?,?) "
            "ON CONFLICT(user_uuid) DO UPDATE SET token=excluded.token, "
            "created_at=excluded.created_at, revoked_at=excluded.revoked_at",
            (user_uuid, payload.get("token"), payload.get("created_at") or now_ms(),
             payload.get("revoked_at")),
        )

    def _upsert_client_profile(self, payload: dict, profile_id: str) -> None:
        cols = ("id", "name", "mode", "enabled", "split_enabled", "route_ru",
                "route_non_ru", "route_private", "sort_order", "created_at",
                "updated_at", "updated_by")
        values = []
        for col in cols:
            value = payload.get(col)
            if col == "id":
                value = profile_id
            elif col in ("enabled", "split_enabled"):
                value = 1 if value else 0
            elif col in ("sort_order",):
                value = int(value or 0)
            elif col in ("created_at", "updated_at"):
                value = int(value or now_ms())
            elif col == "route_private" and not value:
                value = "direct"
            elif col == "mode" and not value:
                value = "proxy"
            values.append(value)
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        self.conn.execute(
            f"INSERT INTO client_profiles({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}",
            values,
        )

    def _upsert_route(self, payload: dict, route_id: str) -> None:
        cols = ("id", "name", "hops", "sort_order", "created_at", "updated_at", "updated_by")
        values = []
        for col in cols:
            value = payload.get(col)
            if col == "id":
                value = route_id
            elif col == "hops":
                value = value if isinstance(value, str) else json_text(value or [])
            elif col == "sort_order":
                value = int(value or 0)
            elif col in ("created_at", "updated_at"):
                value = int(value or now_ms())
            values.append(value)
        placeholders = ",".join("?" for _ in cols)
        updates = ",".join(f"{c}=excluded.{c}" for c in cols if c != "id")
        self.conn.execute(
            f"INSERT INTO routes({','.join(cols)}) VALUES({placeholders}) "
            f"ON CONFLICT(id) DO UPDATE SET {updates}",
            values,
        )

    # ── users ────────────────────────────────────────────────────────

    @staticmethod
    def _row_to_user(row: sqlite3.Row) -> User:
        return User(
            uuid=row["uuid"],
            name=row["name"],
            note=row["note"],
            enabled=bool(row["enabled"]),
            expires_at=row["expires_at"],
            max_devices=row["max_devices"],
            visible_nodes=json_load(row["visible_nodes"], []),
            allowed_hops=json_load(row["allowed_hops"], []),
            allowed_exits=json_load(row["allowed_exits"], []),
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            updated_by=row["updated_by"],
            deleted=bool(row["deleted"]),
        )

    def create_user(self, name: str, note: str = "", expires_at: Optional[int] = None,
                    max_devices: int = 0, visible_nodes: Optional[list[str]] = None,
                    allowed_hops: Optional[list[str]] = None,
                    allowed_exits: Optional[list[str]] = None,
                    actor: str = "system") -> tuple[User, bytes]:
        user_uuid = str(uuidlib.uuid4())
        secret = os.urandom(32)
        ts = now_ms()
        with self.lock:
            self.conn.execute(
                "INSERT INTO users(uuid,name,note,enabled,expires_at,max_devices,"
                "visible_nodes,allowed_hops,allowed_exits,secret_enc,created_at,updated_at,"
                "updated_by,deleted) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                (user_uuid, name, note, 1, expires_at, max_devices,
                 json_text(visible_nodes or []), json_text(allowed_hops or []),
                 json_text(allowed_exits or []), self._encrypt_secret(user_uuid, secret),
                 ts, ts, self.node_id),
            )
            self.conn.execute(
                "INSERT INTO subscriptions(user_uuid,token,created_at) VALUES(?,?,?)",
                (user_uuid, secrets.token_urlsafe(32), ts),
            )
            self.conn.commit()
        self._log_op("user", user_uuid, "upsert", self._user_payload(user_uuid))
        self._log_op("subscription", user_uuid, "upsert", self._subscription_payload(user_uuid))
        self.audit(actor, "create_user", user_uuid, name)
        user = self.get_user(user_uuid)
        assert user is not None
        return user, secret

    def get_user(self, user_uuid: str) -> Optional[User]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM users WHERE uuid=? AND deleted=0", (user_uuid,)
            ).fetchone()
        return self._row_to_user(row) if row else None

    def list_users(self) -> list[User]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM users WHERE deleted=0 ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_user(r) for r in rows]

    def update_user(self, user_uuid: str, **fields: Any) -> Optional[User]:
        allowed = {"name", "note", "enabled", "expires_at", "max_devices",
                   "visible_nodes", "allowed_hops", "allowed_exits"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_user(user_uuid)
        sets = []
        values: list[Any] = []
        for key, value in updates.items():
            if key in ("visible_nodes", "allowed_hops", "allowed_exits"):
                value = json_text(value)
            if key == "enabled":
                value = 1 if value else 0
            sets.append(f"{key}=?")
            values.append(value)
        sets.append("updated_at=?")
        values.append(self.next_hlc())
        sets.append("updated_by=?")
        values.append(self.node_id)
        values.append(user_uuid)
        with self.lock:
            self.conn.execute(
                f"UPDATE users SET {', '.join(sets)} WHERE uuid=? AND deleted=0", values
            )
            self.conn.commit()
        self.audit("admin", "update_user", user_uuid, json_text(updates))
        self._log_op("user", user_uuid, "upsert", self._user_payload(user_uuid))
        return self.get_user(user_uuid)

    def set_enabled(self, user_uuid: str, enabled: bool, actor: str = "admin") -> Optional[User]:
        user = self.update_user(user_uuid, enabled=enabled)
        self.audit(actor, "enable_user" if enabled else "disable_user", user_uuid)
        return user

    def rotate_secret(self, user_uuid: str, actor: str = "admin") -> Optional[bytes]:
        secret = os.urandom(32)
        with self.lock:
            self.conn.execute(
                "UPDATE users SET secret_enc=?, updated_at=?, updated_by=? "
                "WHERE uuid=? AND deleted=0",
                (self._encrypt_secret(user_uuid, secret), self.next_hlc(),
                 self.node_id, user_uuid),
            )
            self.conn.commit()
        self._log_op("user", user_uuid, "upsert", self._user_payload(user_uuid))
        self.audit(actor, "rotate_secret", user_uuid)
        return secret

    def delete_user(self, user_uuid: str, actor: str = "admin") -> bool:
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM users WHERE uuid=? AND deleted=0", (user_uuid,)
            )
            self.conn.execute(
                "INSERT OR REPLACE INTO tombstones(uuid,deleted_at) VALUES(?,?)",
                (user_uuid, now_ms()),
            )
            self.conn.commit()
            deleted = cur.rowcount > 0
        if deleted:
            self._log_op("user", user_uuid, "delete", {})
            self.audit(actor, "delete_user", user_uuid)
        return deleted

    # ── devices ──────────────────────────────────────────────────────

    def register_device(self, user_uuid: str, device_id: str,
                        name: str = "", ip: str = "") -> tuple[bool, str]:
        """Регистрирует устройство при первом запросе. Возвращает (ok, reason)."""
        created = False
        with self.lock:
            user = self.get_user(user_uuid)
            if user is None:
                return False, "unknown_user"
            if not user.enabled:
                return False, "disabled"
            if user.expires_at and user.expires_at < now_ms():
                return False, "expired"
            row = self.conn.execute(
                "SELECT * FROM devices WHERE device_id=?", (device_id,)
            ).fetchone()
            if row is not None:
                if row["user_uuid"] != user_uuid:
                    return False, "device_owner_mismatch"
                self.conn.execute(
                    "UPDATE devices SET last_seen_at=?, last_ip=?, updated_at=? WHERE device_id=?",
                    (now_ms(), ip, now_ms(), device_id),
                )
                self.conn.commit()
                return True, "ok"
            if user.max_devices > 0:
                count = self.conn.execute(
                    "SELECT COUNT(*) AS c FROM devices WHERE user_uuid=? AND enabled=1",
                    (user_uuid,),
                ).fetchone()["c"]
                if count >= user.max_devices:
                    return False, "device_limit"
            self.conn.execute(
                "INSERT INTO devices(device_id,user_uuid,name,enabled,created_at,updated_at,"
                "last_seen_at,last_ip) VALUES(?,?,?,1,?,?,?,?)",
                (device_id, user_uuid, name, now_ms(), now_ms(), now_ms(), ip),
            )
            self.conn.commit()
            created = True
        if created:
            self._log_op("device", device_id, "upsert", self._device_payload(device_id))
        self.audit("device", "register_device", user_uuid, device_id)
        return True, "ok"

    def list_devices(self, user_uuid: str) -> list[Device]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM devices WHERE user_uuid=? ORDER BY created_at DESC",
                (user_uuid,),
            ).fetchall()
        return [
            Device(
                device_id=r["device_id"], user_uuid=r["user_uuid"], name=r["name"],
                enabled=bool(r["enabled"]), created_at=r["created_at"],
                updated_at=r["updated_at"], last_seen_at=r["last_seen_at"],
                last_ip=r["last_ip"],
            )
            for r in rows
        ]

    def revoke_device(self, user_uuid: str, device_id: str, actor: str = "admin") -> bool:
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM devices WHERE device_id=? AND user_uuid=?",
                (device_id, user_uuid),
            )
            self.conn.commit()
        if cur.rowcount:
            self._log_op("device", device_id, "delete", {})
            self.audit(actor, "revoke_device", user_uuid, device_id)
        return cur.rowcount > 0

    # ── subscriptions ────────────────────────────────────────────────

    def subscription_token(self, user_uuid: str) -> Optional[str]:
        with self.lock:
            row = self.conn.execute(
                "SELECT token FROM subscriptions WHERE user_uuid=? AND revoked_at IS NULL",
                (user_uuid,),
            ).fetchone()
            if row:
                return row["token"]
            if self.get_user(user_uuid) is None:
                return None
            token = secrets.token_urlsafe(32)
            self.conn.execute(
                "INSERT INTO subscriptions(user_uuid,token,created_at) VALUES(?,?,?) "
                "ON CONFLICT(user_uuid) DO UPDATE SET token=excluded.token, revoked_at=NULL, "
                "created_at=excluded.created_at",
                (user_uuid, token, now_ms()),
            )
            self.conn.commit()
        self._log_op("subscription", user_uuid, "upsert", self._subscription_payload(user_uuid))
        return token

    def revoke_subscription(self, user_uuid: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE subscriptions SET revoked_at=? WHERE user_uuid=?",
                (now_ms(), user_uuid),
            )
            self.conn.commit()
        self._log_op("subscription", user_uuid, "upsert", self._subscription_payload(user_uuid))
        self.audit("admin", "revoke_subscription", user_uuid)

    def get_user_by_token(self, token: str) -> Optional[User]:
        with self.lock:
            row = self.conn.execute(
                "SELECT u.* FROM subscriptions s JOIN users u ON u.uuid=s.user_uuid "
                "WHERE s.token=? AND s.revoked_at IS NULL AND u.deleted=0",
                (token,),
            ).fetchone()
        return self._row_to_user(row) if row else None

    # ── client profiles ──────────────────────────────────────────────

    @staticmethod
    def _row_to_client_profile(row: sqlite3.Row) -> ClientProfile:
        return ClientProfile(
            id=row["id"],
            name=row["name"],
            mode=row["mode"],
            enabled=bool(row["enabled"]),
            split_enabled=bool(row["split_enabled"]),
            route_ru=row["route_ru"],
            route_non_ru=row["route_non_ru"],
            route_private=row["route_private"],
            sort_order=row["sort_order"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
            updated_by=row["updated_by"],
        )

    def list_client_profiles(self) -> list[ClientProfile]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM client_profiles ORDER BY sort_order, created_at"
            ).fetchall()
        return [self._row_to_client_profile(r) for r in rows]

    def get_client_profile(self, profile_id: str) -> Optional[ClientProfile]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM client_profiles WHERE id=?", (profile_id,)
            ).fetchone()
        return self._row_to_client_profile(row) if row else None

    def create_client_profile(self, name: str, mode: str = "proxy",
                              split_enabled: bool = False,
                              route_ru: str = "", route_non_ru: str = "",
                              route_private: str = "direct",
                              sort_order: Optional[int] = None,
                              actor: str = "admin") -> ClientProfile:
        profile_id = str(uuidlib.uuid4())
        ts = now_ms()
        if sort_order is None:
            with self.lock:
                row = self.conn.execute(
                    "SELECT COALESCE(MAX(sort_order), -1) + 1 AS n FROM client_profiles"
                ).fetchone()
            sort_order = int(row["n"])
        with self.lock:
            self.conn.execute(
                "INSERT INTO client_profiles(id,name,mode,enabled,split_enabled,"
                "route_ru,route_non_ru,route_private,sort_order,created_at,updated_at,"
                "updated_by) VALUES(?,?,?,1,?,?,?,?,?,?,?,?)",
                (profile_id, name, mode, 1 if split_enabled else 0, route_ru,
                 route_non_ru, route_private, sort_order, ts, ts, self.node_id),
            )
            self.conn.commit()
        self._log_op("profile", profile_id, "upsert", self._client_profile_payload(profile_id))
        self.audit(actor, "create_profile", profile_id, name)
        return self.get_client_profile(profile_id)

    def update_client_profile(self, profile_id: str, **fields) -> Optional[ClientProfile]:
        allowed = {"name", "mode", "enabled", "split_enabled", "route_ru",
                   "route_non_ru", "route_private", "sort_order"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return self.get_client_profile(profile_id)
        sets, values = [], []
        for key, value in updates.items():
            if key in ("enabled", "split_enabled"):
                value = 1 if value else 0
            sets.append(f"{key}=?")
            values.append(value)
        sets.append("updated_at=?")
        values.append(self.next_hlc())
        sets.append("updated_by=?")
        values.append(self.node_id)
        values.append(profile_id)
        with self.lock:
            self.conn.execute(
                f"UPDATE client_profiles SET {', '.join(sets)} WHERE id=?", values
            )
            self.conn.commit()
        self._log_op("profile", profile_id, "upsert", self._client_profile_payload(profile_id))
        return self.get_client_profile(profile_id)

    def delete_client_profile(self, profile_id: str, actor: str = "admin") -> bool:
        with self.lock:
            cur = self.conn.execute("DELETE FROM client_profiles WHERE id=?", (profile_id,))
            self.conn.commit()
        if cur.rowcount:
            self._log_op("profile", profile_id, "delete", {})
            self.audit(actor, "delete_profile", profile_id)
        return cur.rowcount > 0

    def _client_profile_payload(self, profile_id: str) -> dict:
        profile = self.get_client_profile(profile_id)
        return profile.to_public() if profile else {}

    # ── routes (конструктор цепочек) ─────────────────────────────────

    @staticmethod
    def _row_to_route(row: sqlite3.Row) -> Route:
        return Route(
            id=row["id"], name=row["name"], hops=json_load(row["hops"], []),
            sort_order=row["sort_order"], created_at=row["created_at"],
            updated_at=row["updated_at"], updated_by=row["updated_by"],
        )

    def list_routes(self) -> list[Route]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM routes ORDER BY sort_order, created_at"
            ).fetchall()
        return [self._row_to_route(r) for r in rows]

    def get_route(self, route_id: str) -> Optional[Route]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM routes WHERE id=?", (route_id,)).fetchone()
        return self._row_to_route(row) if row else None

    def get_route_by_name(self, name: str) -> Optional[Route]:
        with self.lock:
            row = self.conn.execute("SELECT * FROM routes WHERE name=?", (name,)).fetchone()
        return self._row_to_route(row) if row else None

    def create_route(self, name: str, hops: list, sort_order: Optional[int] = None,
                     actor: str = "admin") -> Route:
        route_id = str(uuidlib.uuid4())
        ts = now_ms()
        if sort_order is None:
            with self.lock:
                row = self.conn.execute(
                    "SELECT COALESCE(MAX(sort_order), -1) + 1 AS n FROM routes"
                ).fetchone()
            sort_order = int(row["n"])
        with self.lock:
            self.conn.execute(
                "INSERT INTO routes(id,name,hops,sort_order,created_at,updated_at,updated_by) "
                "VALUES(?,?,?,?,?,?,?)",
                (route_id, name, json_text(hops or []), sort_order, ts, ts, self.node_id),
            )
            self.conn.commit()
        self._log_op("route", route_id, "upsert", self._route_payload(route_id))
        self.audit(actor, "create_route", route_id, name)
        return self.get_route(route_id)

    def update_route(self, route_id: str, name: Optional[str] = None,
                     hops: Optional[list] = None,
                     sort_order: Optional[int] = None) -> Optional[Route]:
        sets, values = [], []
        if name is not None:
            sets.append("name=?"); values.append(name)
        if hops is not None:
            sets.append("hops=?"); values.append(json_text(hops))
        if sort_order is not None:
            sets.append("sort_order=?"); values.append(int(sort_order))
        if not sets:
            return self.get_route(route_id)
        sets.append("updated_at=?"); values.append(self.next_hlc())
        sets.append("updated_by=?"); values.append(self.node_id)
        values.append(route_id)
        with self.lock:
            self.conn.execute(
                f"UPDATE routes SET {', '.join(sets)} WHERE id=?", values
            )
            self.conn.commit()
        self._log_op("route", route_id, "upsert", self._route_payload(route_id))
        return self.get_route(route_id)

    def delete_route(self, route_id: str, actor: str = "admin") -> bool:
        with self.lock:
            cur = self.conn.execute("DELETE FROM routes WHERE id=?", (route_id,))
            self.conn.commit()
        if cur.rowcount:
            self._log_op("route", route_id, "delete", {})
            self.audit(actor, "delete_route", route_id)
        return cur.rowcount > 0

    def _route_payload(self, route_id: str) -> dict:
        route = self.get_route(route_id)
        return route.to_public() if route else {}

    # ── audit read ───────────────────────────────────────────────────

    def recent_audit(self, limit: int = 100) -> list[sqlite3.Row]:
        with self.lock:
            return self.conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def close(self) -> None:
        with self.lock:
            try:
                self.conn.close()
            except Exception:
                pass
