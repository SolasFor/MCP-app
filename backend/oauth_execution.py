"""Local-only, single-use approval workflow for remote OAuth execution.

No internet-exposed admin endpoint: only Windows GUI opens and approves pending
requests in the same user-owned SQLite database. All OAuth-approved clients have the SAME fixed Windows + SSH capabilities.
Each executable request must match an exact OWNER-configured template and,
for SSH, an exact host. Each attempt requires an additional short-lived local
approval of the exact request; the server does NOT wait over Cloudflare.
"""
from __future__ import annotations

import hashlib
import secrets
import time
from typing import Literal

try:
    from .oauth_store import OAuthStore
except ImportError:
    from oauth_store import OAuthStore

ActionKind = Literal["windows", "ssh"]
REQUEST_TTL = 180
MAX_PENDING = 32
MAX_RULES = 24
MAX_RULE_SIZE = 512


def _digest(ticket: str) -> str:
    return hashlib.sha256(ticket.encode("utf-8")).hexdigest()


def _parse_rules(text: str, *, host: bool = False) -> tuple[str, ...]:
    """Exact, per-line whitelist; no wildcards, control chars or shell defaults."""
    if not isinstance(text, str) or len(text) > MAX_RULES * MAX_RULE_SIZE:
        raise ValueError("Invalid rule list")
    rules: list[str] = []
    for line in text.splitlines():
        rule = line.strip()
        if not rule:
            continue
        if len(rule) > MAX_RULE_SIZE or any(ch in rule for ch in ("\x00", "\r", "\t")):
            raise ValueError("Invalid allowlist entry")
        if "*" in rule or "?" in rule:
            raise ValueError("Wildcards are not allowed")
        if host and any(ch in rule for ch in (" ", "/", "\\", ":", "@")):
            raise ValueError("SSH hosts must be exact hostnames or SSH aliases")
        if rule not in rules:
            rules.append(rule)
        if len(rules) > MAX_RULES:
            raise ValueError("Too many allowlist entries")
    return tuple(rules)


class ExecutionApprovals:
    """A constrained authorization layer attached to an existing OAuthStore."""

    def __init__(self, store: OAuthStore) -> None:
        self.store = store
        with store._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS exec_policy(
                    issuer TEXT PRIMARY KEY,
                    encrypted BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS exec_requests(
                    digest TEXT PRIMARY KEY,
                    issuer TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    encrypted BLOB NOT NULL,
                    created INTEGER NOT NULL,
                    expires INTEGER NOT NULL,
                    approved INTEGER NOT NULL DEFAULT 0 CHECK(approved IN (0,1))
                );
                CREATE INDEX IF NOT EXISTS idx_exec_pending ON
                    exec_requests(issuer,expires,approved);
            """)
            # Existing databases may contain the superseded per-client grant
            # table. Its values are deliberately ignored: access is fixed.
            db.execute("""
                DELETE FROM exec_requests
                WHERE issuer=? AND client_id NOT IN (
                    SELECT client_id FROM clients WHERE issuer=?
                )""", (store.issuer, store.issuer))

    def policy(self) -> dict[str, tuple[str, ...]]:
        with self.store._db() as db:
            row = db.execute("SELECT encrypted FROM exec_policy WHERE issuer=?",
                             (self.store.issuer,)).fetchone()
        if not row:
            return {"windows": (), "hosts": (), "ssh_commands": ()}
        payload = self.store._decrypt(row[0])
        return {key: tuple(payload.get(key, ()))
                for key in ("windows", "hosts", "ssh_commands")}

    def set_policy(self, *, windows: str, hosts: str, ssh_commands: str) -> None:
        """GUI-only policy mutation. Invalidate all pending approvals on change."""
        policy = {
            "windows": _parse_rules(windows),
            "hosts": _parse_rules(hosts, host=True),
            "ssh_commands": _parse_rules(ssh_commands),
        }
        encrypted = self.store._encrypt(policy)
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR REPLACE INTO exec_policy(issuer,encrypted) VALUES (?,?)",
                       (self.store.issuer, encrypted))
            db.execute("DELETE FROM exec_requests WHERE issuer=?", (self.store.issuer,))

    def client_approved(self, client_id: str) -> bool:
        """Only browser-consented OAuth clients are allowed to request actions."""
        if not isinstance(client_id, str) or not client_id or client_id == "mcp-app-user":
            return False
        with self.store._db() as db:
            return bool(db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=? AND approved_at IS NOT NULL",
                (self.store.issuer, client_id),
            ).fetchone())

    def can_request(self, client_id: str, kind: ActionKind, *,
                    command: str, host: str = "", user: str = "", port: int = 22) -> bool:
        if kind not in ("windows", "ssh") or client_id == "mcp-app-user":
            return False
        if not isinstance(command, str) or not command or len(command) > MAX_RULE_SIZE:
            return False
        if not isinstance(port, int) or not (1 <= port <= 65535) or not isinstance(user, str):
            return False
        if len(user) > 64 or any(ch in user for ch in ("/", "\\", " ", "@", "\x00")):
            return False
        if not self.client_approved(client_id):
            return False
        policy = self.policy()
        if kind == "windows":
            return command in policy["windows"] and not host and not user
        return host in policy["hosts"] and command in policy["ssh_commands"]

    @staticmethod
    def _action(kind: ActionKind, command: str, host: str, user: str, port: int) -> dict:
        return {"kind": kind, "command": command, "host": host,
                "user": user, "port": port}

    def request(self, client_id: str, kind: ActionKind, *, command: str,
                host: str = "", user: str = "", port: int = 22) -> str:
        if not self.can_request(client_id, kind, command=command,
                                host=host, user=user, port=port):
            raise PermissionError("Execution is disabled or not on the exact allowlist")
        ticket = secrets.token_urlsafe(24)
        now = int(time.time())
        payload = self._action(kind, command, host, user, port)
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM exec_requests WHERE expires<?", (now,))
            count = db.execute(
                "SELECT count(*) FROM exec_requests WHERE issuer=?",
                (self.store.issuer,),
            ).fetchone()[0]
            if count >= MAX_PENDING:
                raise RuntimeError("Too many pending approvals")
            db.execute("""
                INSERT INTO exec_requests
                (digest,issuer,client_id,encrypted,created,expires,approved)
                VALUES (?,?,?,?,?,?,0)
            """, (_digest(ticket), self.store.issuer, client_id,
                  self.store._encrypt(payload), now, now + REQUEST_TTL))
        return ticket

    def pending(self) -> list[dict]:
        now = int(time.time())
        with self.store._db() as db:
            rows = db.execute("""
                SELECT r.digest,r.client_id,r.encrypted,r.created,r.expires,r.approved
                FROM exec_requests r JOIN clients c
                ON c.issuer=r.issuer AND c.client_id=r.client_id
                WHERE r.issuer=? AND r.expires>? AND c.approved_at IS NOT NULL
                ORDER BY r.created ASC
            """, (self.store.issuer, now)).fetchall()
        return [dict(ticket_hash=digest, client_id=cid,
                     **self.store._decrypt(enc), created=created,
                     expires=expires, approved=bool(approved))
                for digest,cid,enc,created,expires,approved in rows]

    def decision(self, ticket_hash: str, *, approve: bool) -> bool:
        """Local GUI approval; no route for remote clients to call this."""
        now = int(time.time())
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT r.client_id,r.encrypted,r.approved
                FROM exec_requests r JOIN clients c
                ON c.issuer=r.issuer AND c.client_id=r.client_id
                WHERE r.digest=? AND r.issuer=? AND r.expires>?
                      AND c.approved_at IS NOT NULL
            """, (ticket_hash, self.store.issuer, now)).fetchone()
            if not row:
                return False
            if not approve:
                db.execute("DELETE FROM exec_requests WHERE digest=?", (ticket_hash,))
                return True
            if row[2]:
                return False
            payload = self.store._decrypt(row[1])
            if not self.can_request(row[0], payload["kind"],
                                    command=payload["command"], host=payload["host"],
                                    user=payload["user"], port=payload["port"]):
                # The writer lock prevents another process from changing
                # client approval or policy while this decision commits.
                return False
            db.execute("UPDATE exec_requests SET approved=1 WHERE digest=?",
                       (ticket_hash,))
            return True

    def consume(self, ticket: str, client_id: str, kind: ActionKind, *,
                command: str, host: str = "", user: str = "", port: int = 22) -> bool:
        """One-time consume bound to exact client and every execution argument."""
        if not ticket or not self.can_request(client_id, kind, command=command,
                                              host=host, user=user, port=port):
            return False
        now = int(time.time())
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("""
                SELECT encrypted,expires,approved FROM exec_requests
                WHERE digest=? AND issuer=? AND client_id=?
            """, (_digest(ticket), self.store.issuer, client_id)).fetchone()
            if not row or row[1] <= now or not row[2]:
                return False
            if self.store._decrypt(row[0]) != self._action(kind, command, host, user, port):
                return False
            # Consume before executing. Replays cannot run twice.
            db.execute("DELETE FROM exec_requests WHERE digest=?",
                       (_digest(ticket),))
            return True
