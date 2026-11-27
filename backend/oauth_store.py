"""Local OAuth client/token storage, shared by GUI and backend via SQLite.

Windows: Fernet data key is wrapped with the current user's DPAPI key, and files
receive user-only ACLs.
POSIX: data key is stored in a user-private (0700) directory (0600 key file);
this is not OS keychain protection and is documented as such.

Only digests of OAuth access/refresh tokens are written to disk, never the
bearer tokens themselves. Client metadata, including possible DCR secrets,
is encrypted. All queries are scoped to the exact issuer URL.
"""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from cryptography.fernet import Fernet
from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from app.core.redaction import SecretRedactor
from app.platform import get_platform

SCHEMA_VERSION = 3
_KEY_PREFIX_WIN = b"DPAPI1:"
_KEY_PREFIX_POSIX = b"POSIX1:"


def canonical_oauth_urls(url: str) -> tuple[str, str]:
    """Return canonical ``(issuer, resource_url)`` shared between GUI and backend."""
    raw = (url or "").strip()
    if not raw:
        return "", ""
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    if scheme not in ("http", "https") or not host:
        cleaned = raw.rstrip("/")
        return cleaned, cleaned
    try:
        port = parts.port
    except ValueError:
        port = None
    default_port = 80 if scheme == "http" else 443
    host_fmt = f"[{host}]" if ":" in host else host
    netloc = host_fmt if (port is None or port == default_port) else f"{host_fmt}:{port}"
    issuer = urlunsplit((scheme, netloc, "", "", ""))
    path = parts.path.rstrip("/")
    resource_url = f"{issuer}{path}" if path else issuer
    return issuer, resource_url


def default_store_path() -> Path:
    env_override = os.environ.get("MCP_OAUTH_STORE_PATH", "").strip()
    if env_override:
        return Path(env_override).expanduser()
    from app.paths import user_data_dir

    return user_data_dir() / "oauth" / "connections.sqlite3"


def _user_private(path: Path, *, directory: bool = False) -> None:
    try:
        get_platform().restrict_path_acl(path, is_dir=directory)
    except OSError:
        pass


def _win_dpapi(blob: bytes, *, decrypt: bool) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("Windows DPAPI is only supported on Windows")
    platform = get_platform()
    if decrypt:
        return platform.dpapi_unprotect(blob)
    return platform.dpapi_protect(blob, "MCPApp OAuth key")


def _load_or_create_key(db_path: Path) -> bytes:
    key_path = db_path.with_suffix(".key")
    if key_path.exists():
        data = key_path.read_bytes()
        if sys.platform == "win32" and data.startswith(_KEY_PREFIX_WIN):
            return _win_dpapi(data[len(_KEY_PREFIX_WIN):], decrypt=True)
        if sys.platform != "win32" and data.startswith(_KEY_PREFIX_POSIX):
            if key_path.stat().st_mode & 0o077:
                raise PermissionError("OAuth key must not be group/world readable")
            return data[len(_KEY_PREFIX_POSIX):]
        raise ValueError("OAuth storage key is not readable on this platform")
    # Do not silently replace a lost key for an existing DB: that could discard
    # active authorizations while leaving old data unreadable.
    if db_path.exists() and db_path.stat().st_size:
        raise FileNotFoundError("OAuth encryption key missing for existing database")
    key = Fernet.generate_key()
    stored = (
        _KEY_PREFIX_WIN + _win_dpapi(key, decrypt=False)
        if sys.platform == "win32"
        else _KEY_PREFIX_POSIX + key
    )
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(stored)
    _user_private(key_path)
    return key


def _digest(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class OAuthStore:
    def __init__(self, path: str | Path, issuer: str, resource_url: str) -> None:
        self.path = Path(path).expanduser().resolve()
        canon_issuer, canon_resource = canonical_oauth_urls(resource_url or issuer)
        if canon_issuer and (not issuer or canonical_oauth_urls(issuer)[0] == canon_issuer):
            self.issuer = canon_issuer
            self.resource_url = canon_resource
        else:
            self.issuer = issuer.rstrip("/")
            self.resource_url = resource_url.rstrip("/")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _user_private(self.path.parent, directory=True)
        self._cipher = Fernet(_load_or_create_key(self.path))
        self._apply_migrations()
        _user_private(self.path)

    def _apply_migrations(self) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations(
                    version INTEGER PRIMARY KEY,
                    applied_at INTEGER NOT NULL,
                    description TEXT NOT NULL
                )
            """)
            applied = {
                row[0] for row in db.execute("SELECT version FROM schema_migrations").fetchall()
            }
            if 1 not in applied:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS meta(
                        issuer TEXT PRIMARY KEY, owner_fingerprint TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS clients(
                        issuer TEXT NOT NULL, client_id TEXT NOT NULL,
                        encrypted BLOB NOT NULL, registered_at INTEGER NOT NULL,
                        approved_at INTEGER,
                        PRIMARY KEY(issuer, client_id)
                    );
                    CREATE TABLE IF NOT EXISTS tokens(
                        digest TEXT PRIMARY KEY, issuer TEXT NOT NULL,
                        client_id TEXT NOT NULL, kind TEXT NOT NULL,
                        encrypted BLOB NOT NULL, expires_at INTEGER NOT NULL,
                        family TEXT NOT NULL
                    );
                    DROP TABLE IF EXISTS client_permissions;
                    CREATE INDEX IF NOT EXISTS idx_token_family ON tokens(issuer, family);
                    CREATE INDEX IF NOT EXISTS idx_client_tokens ON tokens(issuer, client_id);
                """)
                db.execute(
                    "INSERT OR IGNORE INTO schema_migrations VALUES (?,?,?)",
                    (1, int(time.time()), "Initial OAuth tables"),
                )
            if 2 not in applied:
                db.executescript("""
                    CREATE TABLE IF NOT EXISTS exec_client_allowlists(
                        issuer TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        encrypted BLOB NOT NULL,
                        PRIMARY KEY(issuer, client_id)
                    );
                    CREATE TABLE IF NOT EXISTS exec_temp_grants(
                        grant_id TEXT PRIMARY KEY,
                        issuer TEXT NOT NULL,
                        client_id TEXT NOT NULL,
                        encrypted BLOB NOT NULL,
                        expires_at INTEGER NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS runtime_control(
                        issuer TEXT PRIMARY KEY,
                        emergency_stop INTEGER NOT NULL DEFAULT 0,
                        reason TEXT NOT NULL DEFAULT '',
                        updated_at INTEGER NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_temp_grants_client
                        ON exec_temp_grants(issuer, client_id, expires_at);
                """)
                db.execute(
                    "INSERT OR IGNORE INTO schema_migrations VALUES (?,?,?)",
                    (2, int(time.time()), "Per-client allowlists, temporary grants, emergency stop"),
                )
            if 3 not in applied:
                cols = {row[1] for row in db.execute("PRAGMA table_info(meta)").fetchall()}
                if "resource_url" not in cols:
                    db.execute("ALTER TABLE meta ADD COLUMN resource_url TEXT NOT NULL DEFAULT ''")
                db.execute(
                    "INSERT OR IGNORE INTO schema_migrations VALUES (?,?,?)",
                    (3, int(time.time()), "Separate owner rotation from resource URL changes"),
                )

    def schema_version(self) -> int:
        with self._db() as db:
            row = db.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0) if row else 0

    @contextmanager
    def _db(self):
        db = sqlite3.connect(str(self.path), timeout=10)
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def _encrypt(self, value: dict) -> bytes:
        return self._cipher.encrypt(json.dumps(value, ensure_ascii=False).encode("utf-8"))

    def _decrypt(self, value: bytes) -> dict:
        return json.loads(self._cipher.decrypt(value).decode("utf-8"))

    @staticmethod
    def _clear_exec_records(db, issuer: str, client_id: str | None = None) -> None:
        # OAuthStore also works without the optional execution module/tables.
        tables = (
            "exec_grants",
            "exec_requests",
            "exec_client_profiles",
            "exec_client_allowlists",
            "exec_client_policies",
            "exec_temp_grants",
        )
        placeholders = ",".join("?" for _ in tables)
        existing = {
            row[0]
            for row in db.execute(
                f"SELECT name FROM sqlite_master WHERE type='table' AND name IN ({placeholders})",
                tables,
            )
        }
        for table in tables:
            if table not in existing:
                continue
            sql = f"DELETE FROM {table} WHERE issuer=?"
            args: tuple[str, ...] = (issuer,)
            if client_id is not None:
                sql += " AND client_id=?"
                args = (issuer, client_id)
            db.execute(sql, args)

    def set_emergency_stop(self, active: bool, reason: str = "") -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO runtime_control(issuer, emergency_stop, reason, updated_at) "
                "VALUES (?,?,?,?)",
                (self.issuer, 1 if active else 0, str(reason)[:256], int(time.time())),
            )

    def emergency_stop_state(self) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT emergency_stop, reason, updated_at FROM runtime_control WHERE issuer=?",
                (self.issuer,),
            ).fetchone()
        if not row:
            return {"active": False, "reason": "", "updated_at": None}
        return {"active": bool(row[0]), "reason": row[1], "updated_at": row[2]}

    def bind_owner(self, secret: str) -> None:
        """Rotate owner token or detect resource URL change with explicit revocation semantics.

        Policy:
        - Owner token rotation (same issuer & resource_url): immediately revokes all
          issued OAuth access/refresh tokens and resets client ``approved_at=NULL``
          plus execution overrides, while preserving DCR client registrations so
          external AI clients can reconnect cleanly via ``/authorize`` + ``/oauth/consent``.
        - Resource URL change on the same issuer: wipes tokens, client registrations,
          and execution records completely.
        """
        v2_fp = _digest("MCPApp/OAuth/owner/v2\0" + secret)
        v1_fp = _digest("MCPApp/OAuth/owner/v1\0" + secret + "\0" + self.resource_url)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT owner_fingerprint, resource_url FROM meta WHERE issuer=?", (self.issuer,)
            ).fetchone()
            if existing:
                existing_fp = str(existing[0] or "")
                existing_res = str(existing[1] or "")
                if existing_fp == v2_fp and existing_res == self.resource_url:
                    return
                if existing_fp in (v2_fp, v1_fp) and (not existing_res or existing_res == self.resource_url):
                    db.execute(
                        "INSERT OR REPLACE INTO meta(issuer, owner_fingerprint, resource_url) VALUES (?, ?, ?)",
                        (self.issuer, v2_fp, self.resource_url),
                    )
                    return
                resource_changed = bool(existing_res and existing_res != self.resource_url)
                if not existing_res and not resource_changed:
                    # Legacy v1 row without resource_url column: detect resource mismatch from stored tokens.
                    for (enc,) in db.execute(
                        "SELECT encrypted FROM tokens WHERE issuer=?", (self.issuer,)
                    ).fetchall():
                        try:
                            tok_res = str(self._decrypt(enc).get("resource") or "").rstrip("/")
                            if tok_res and tok_res != self.resource_url:
                                resource_changed = True
                                break
                        except Exception:  # noqa: BLE001
                            resource_changed = True
                            break
                db.execute("DELETE FROM tokens WHERE issuer=?", (self.issuer,))
                if resource_changed:
                    db.execute("DELETE FROM clients WHERE issuer=?", (self.issuer,))
                else:
                    db.execute("UPDATE clients SET approved_at=NULL WHERE issuer=?", (self.issuer,))
                self._clear_exec_records(db, self.issuer)
            db.execute(
                "INSERT OR REPLACE INTO meta(issuer, owner_fingerprint, resource_url) VALUES (?, ?, ?)",
                (self.issuer, v2_fp, self.resource_url),
            )

    def remove_old_quick_tunnels(self) -> None:
        hostname = (urlsplit(self.issuer).hostname or "").lower()
        if not hostname.endswith(".trycloudflare.com"):
            return
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = [
                row[0]
                for row in db.execute(
                    "SELECT issuer FROM clients UNION SELECT issuer FROM tokens UNION SELECT issuer FROM meta"
                )
            ]
            for origin in old:
                host = (urlsplit(origin).hostname or "").lower()
                if origin != self.issuer and host.endswith(".trycloudflare.com"):
                    db.execute("DELETE FROM clients WHERE issuer=?", (origin,))
                    db.execute("DELETE FROM tokens WHERE issuer=?", (origin,))
                    db.execute("DELETE FROM meta WHERE issuer=?", (origin,))
                    db.execute("DELETE FROM runtime_control WHERE issuer=?", (origin,))
                    self._clear_exec_records(db, origin)

    @classmethod
    def latest_persistent_resource_url(cls, path: str | Path) -> str:
        """Return the latest non-ephemeral resource URL with saved clients if the DB already exists."""
        db_file = Path(path).expanduser()
        if not db_file.is_file() or db_file.stat().st_size == 0:
            return ""
        try:
            conn = sqlite3.connect(str(db_file), timeout=3)
            try:
                rows = conn.execute(
                    """SELECT c.issuer, COALESCE(m.resource_url, ''), MAX(COALESCE(c.approved_at, c.registered_at)) AS ts
                       FROM clients c
                       LEFT JOIN meta m ON m.issuer = c.issuer
                       GROUP BY c.issuer
                       ORDER BY ts DESC"""
                ).fetchall()
            finally:
                conn.close()
        except sqlite3.Error:
            return ""
        for issuer, res_url, _ts in rows:
            iss_str = str(issuer or "").strip()
            host = (urlsplit(iss_str).hostname or "").lower()
            if not iss_str or iss_str == "__default__" or host.endswith(".trycloudflare.com"):
                continue
            return str(res_url or f"{iss_str}/mcp")
        return ""

    def count_clients(self) -> int:
        with self._db() as db:
            return db.execute(
                "SELECT count(*) FROM clients WHERE issuer=?", (self.issuer,)
            ).fetchone()[0]

    def save_client(self, client: OAuthClientInformationFull) -> None:
        if not client.client_id:
            raise ValueError("Client must have an ID")
        payload = self._encrypt(client.model_dump(mode="json"))
        with self._db() as db:
            db.execute(
                """INSERT INTO clients (issuer,client_id,encrypted,registered_at)
                   VALUES (?,?,?,?) ON CONFLICT(issuer,client_id)
                   DO UPDATE SET encrypted=excluded.encrypted""",
                (self.issuer, client.client_id, payload, int(time.time())),
            )

    def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        with self._db() as db:
            record = db.execute(
                "SELECT encrypted FROM clients WHERE issuer=? AND client_id=?",
                (self.issuer, client_id),
            ).fetchone()
        return OAuthClientInformationFull.model_validate(self._decrypt(record[0])) if record else None

    def mark_approved(self, client_id: str) -> None:
        with self._db() as db:
            db.execute(
                "UPDATE clients SET approved_at=? WHERE issuer=? AND client_id=?",
                (int(time.time()), self.issuer, client_id),
            )

    def list_clients(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                """SELECT client_id, encrypted, registered_at, approved_at
                   FROM clients WHERE issuer=?
                   ORDER BY approved_at DESC, registered_at DESC""",
                (self.issuer,),
            ).fetchall()
        return [
            {
                "client_id": ident,
                "client_name": self._decrypt(enc).get("client_name") or "Без названия",
                "registered_at": registered,
                "approved_at": approved,
            }
            for ident, enc, registered, approved in rows
        ]

    def revoke_client(self, client_id: str) -> bool:
        """Transactionally invalidate all client tokens and its registration."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute(
                "DELETE FROM clients WHERE issuer=? AND client_id=?", (self.issuer, client_id)
            )
            db.execute(
                "DELETE FROM tokens WHERE issuer=? AND client_id=?", (self.issuer, client_id)
            )
            self._clear_exec_records(db, self.issuer, client_id)
            return cursor.rowcount > 0

    def save_token(self, token: AccessToken | RefreshToken, kind: str, family: str) -> None:
        if kind not in ("access", "refresh"):
            raise ValueError("Invalid token type")
        if not isinstance(token.resource, str) or token.resource.rstrip("/") != self.resource_url:
            raise ValueError("OAuth resource mismatch")
        payload = token.model_dump(mode="json", exclude={"token"})
        with self._db() as db:
            db.execute(
                """INSERT OR REPLACE INTO tokens
                   (digest,issuer,client_id,kind,encrypted,expires_at,family)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    _digest(token.token),
                    self.issuer,
                    token.client_id,
                    kind,
                    self._encrypt(payload),
                    token.expires_at or 0,
                    family,
                ),
            )

    def get_token(self, raw: str, kind: str):
        with self._db() as db:
            record = db.execute(
                """SELECT encrypted,expires_at,client_id FROM tokens
                   WHERE digest=? AND issuer=? AND kind=?""",
                (_digest(raw), self.issuer, kind),
            ).fetchone()
            if not record:
                return None
            enc, expiry, client_id = record
            if expiry and expiry < time.time():
                db.execute("DELETE FROM tokens WHERE digest=?", (_digest(raw),))
                return None
            active = db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=?",
                (self.issuer, client_id),
            ).fetchone()
            if not active:
                return None
        payload = self._decrypt(enc)
        payload["token"] = raw
        if payload.get("resource", "").rstrip("/") != self.resource_url:
            return None
        cls = AccessToken if kind == "access" else RefreshToken
        return cls.model_validate(payload)

    def family(self, raw: str) -> str | None:
        with self._db() as db:
            row = db.execute(
                "SELECT family FROM tokens WHERE digest=? AND issuer=?",
                (_digest(raw), self.issuer),
            ).fetchone()
        return row[0] if row else None

    def consume_refresh(self, raw: str, client_id: str) -> str | None:
        """Single-use refresh token rotation across concurrent backend requests."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """SELECT family,expires_at FROM tokens
                   WHERE digest=? AND issuer=? AND kind='refresh' AND client_id=?""",
                (_digest(raw), self.issuer, client_id),
            ).fetchone()
            active = db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=?",
                (self.issuer, client_id),
            ).fetchone()
            if not row or not active or (row[1] and row[1] < time.time()):
                return None
            family = row[0]
            db.execute(
                "DELETE FROM tokens WHERE issuer=? AND family=?", (self.issuer, family)
            )
            return family

    def revoke_family(self, family: str) -> None:
        with self._db() as db:
            db.execute(
                "DELETE FROM tokens WHERE issuer=? AND family=?", (self.issuer, family)
            )

    def prune_expired(self) -> None:
        now = int(time.time())
        with self._db() as db:
            db.execute(
                "DELETE FROM tokens WHERE issuer=? AND expires_at>0 AND expires_at<?",
                (self.issuer, now),
            )
            db.execute(
                "DELETE FROM exec_temp_grants WHERE issuer=? AND expires_at<?",
                (self.issuer, now),
            )

    def export_redacted_backup(self, dest_path: Path) -> dict:
        """Write a non-secret backup snapshot (no tokens, digests, client_secrets, or keys)."""
        redactor = SecretRedactor()
        clients_safe = []
        for entry in self.list_clients():
            clients_safe.append({
                "client_id": entry["client_id"],
                "client_name": redactor.redact_text(str(entry["client_name"])),
                "registered_at": entry["registered_at"],
                "approved_at": entry["approved_at"],
            })
        snapshot = {
            "schema_version": self.schema_version(),
            "exported_at": int(time.time()),
            "issuer": self.issuer,
            "resource_url": self.resource_url,
            "emergency_stop": self.emergency_stop_state(),
            "clients": clients_safe,
            "secrets_included": False,
        }
        from app.core.atomic_io import atomic_write_json

        dest = Path(dest_path)
        atomic_write_json(dest, snapshot, indent=2, restrict_acl=True)
        return snapshot
