"""Local OAuth client/token storage, shared by GUI and backend via SQLite.

Windows: Fernet data key is wrapped with the current user's DPAPI key.
POSIX: data key is stored in a user-private (0700) directory (0600 key file);
this is not OS keychain protection and is documented as such.

Only digests of OAuth access/refresh tokens are written to disk, never the
bearer tokens themselves. Client metadata, including possible DCR secrets,
is encrypted. All queries are scoped to the exact issuer URL.
"""
from __future__ import annotations

import ctypes
import hashlib
import json
import os
import sqlite3
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from mcp.server.auth.provider import AccessToken, RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

SCHEMA_VERSION = 1
_KEY_PREFIX_WIN = b"DPAPI1:"
_KEY_PREFIX_POSIX = b"POSIX1:"


def default_store_path() -> Path:
    from app.paths import user_data_dir
    return user_data_dir() / "oauth" / "connections.sqlite3"


def _user_private(path: Path, *, directory: bool = False) -> None:
    if os.name == "nt":
        # The Fernet key is DPAPI-wrapped, even if filesystem ACLs were inherited.
        return
    path.chmod(0o700 if directory else 0o600)


def _win_dpapi(blob: bytes, *, decrypt: bool) -> bytes:
    if sys.platform != "win32":
        raise RuntimeError("Windows DPAPI is only supported on Windows")
    from ctypes import wintypes

    class DataBlob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]

    input_buf = ctypes.create_string_buffer(blob)
    source = DataBlob(len(blob), ctypes.cast(input_buf, ctypes.POINTER(ctypes.c_ubyte)))
    output = DataBlob()
    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
    if decrypt:
        ok = fn(ctypes.byref(source), None, None, None, None, 0x01, ctypes.byref(output))
    else:
        ok = fn(ctypes.byref(source), "MCPApp OAuth key", None, None, None, 0x01, ctypes.byref(output))
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


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
        self.issuer = issuer.rstrip("/")
        self.resource_url = resource_url.rstrip("/")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        _user_private(self.path.parent, directory=True)
        self._cipher = Fernet(_load_or_create_key(self.path))
        with self._db() as db:
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
                CREATE INDEX IF NOT EXISTS idx_token_family ON tokens(issuer, family);
                CREATE INDEX IF NOT EXISTS idx_client_tokens ON tokens(issuer, client_id);
            """)
        _user_private(self.path)

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

    def bind_owner(self, secret: str) -> None:
        """Changing the owner token invalidates all OAuth grants for this issuer."""
        fingerprint = _digest("MCPApp/OAuth/owner/v1\0" + secret + "\0" + self.issuer)
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT owner_fingerprint FROM meta WHERE issuer=?", (self.issuer,)).fetchone()
            if existing and existing[0] != fingerprint:
                db.execute("DELETE FROM tokens WHERE issuer=?", (self.issuer,))
                db.execute("DELETE FROM clients WHERE issuer=?", (self.issuer,))
            db.execute("INSERT OR REPLACE INTO meta VALUES (?, ?)", (self.issuer, fingerprint))

    def remove_old_quick_tunnels(self) -> None:
        hostname = (urlsplit(self.issuer).hostname or "").lower()
        if not hostname.endswith(".trycloudflare.com"):
            return
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            old = [row[0] for row in db.execute("SELECT DISTINCT issuer FROM clients UNION SELECT issuer FROM tokens")]
            for origin in old:
                host = (urlsplit(origin).hostname or "").lower()
                if origin != self.issuer and host.endswith(".trycloudflare.com"):
                    db.execute("DELETE FROM clients WHERE issuer=?", (origin,))
                    db.execute("DELETE FROM tokens WHERE issuer=?", (origin,))
                    db.execute("DELETE FROM meta WHERE issuer=?", (origin,))

    def count_clients(self) -> int:
        with self._db() as db:
            return db.execute("SELECT count(*) FROM clients WHERE issuer=?", (self.issuer,)).fetchone()[0]

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
            db.execute("UPDATE clients SET approved_at=? WHERE issuer=? AND client_id=?",
                       (int(time.time()), self.issuer, client_id))

    def list_clients(self) -> list[dict]:
        with self._db() as db:
            records = db.execute(
                """SELECT client_id,encrypted,registered_at,approved_at
                   FROM clients WHERE issuer=? ORDER BY approved_at DESC, registered_at DESC""",
                (self.issuer,),
            ).fetchall()
        return [{
            "client_id": ident,
            "client_name": self._decrypt(enc).get("client_name") or "Без названия",
            "registered_at": registered,
            "approved_at": approved,
        } for ident, enc, registered, approved in records]

    def revoke_client(self, client_id: str) -> bool:
        """Transactionally invalidate all client tokens and its registration."""
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("DELETE FROM clients WHERE issuer=? AND client_id=?",
                                (self.issuer, client_id))
            db.execute("DELETE FROM tokens WHERE issuer=? AND client_id=?",
                       (self.issuer, client_id))
            return cursor.rowcount > 0

    def save_token(self, token: AccessToken | RefreshToken, kind: str, family: str) -> None:
        if kind not in ("access", "refresh"):
            raise ValueError("Invalid token type")
        if token.resource.rstrip("/") != self.resource_url:
            raise ValueError("OAuth resource mismatch")
        payload = token.model_dump(mode="json", exclude={"token"})
        with self._db() as db:
            db.execute(
                """INSERT OR REPLACE INTO tokens
                   (digest,issuer,client_id,kind,encrypted,expires_at,family)
                   VALUES (?,?,?,?,?,?,?)""",
                (_digest(token.token), self.issuer, token.client_id, kind,
                 self._encrypt(payload), token.expires_at or 0, family),
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
            row = db.execute("SELECT family FROM tokens WHERE digest=? AND issuer=?",
                             (_digest(raw), self.issuer)).fetchone()
        return row[0] if row else None

    def revoke_family(self, family: str) -> None:
        with self._db() as db:
            db.execute("DELETE FROM tokens WHERE issuer=? AND family=?",
                       (self.issuer, family))

    def prune_expired(self) -> None:
        with self._db() as db:
            db.execute("DELETE FROM tokens WHERE issuer=? AND expires_at>0 AND expires_at<?",
                       (self.issuer, int(time.time())))
