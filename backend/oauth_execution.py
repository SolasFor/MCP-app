"""Three owner-selected execution profiles for OAuth MCP clients.

safe: no command/SSH tools (fail-closed fallback for unapproved/corrupt/emergency-stop).
allowlist (default): Windows command lines and SSH host+commands must match exact owner
                     entries (global or per-client); no per-call confirmation.
full: approved OAuth clients can run Windows shell/SSH commands immediately.

Supports per-client allowlist overrides, time-bounded temporary grants, and
emergency-stop fail-closed enforcement. No remote admin route can mutate permissions.
"""
from __future__ import annotations

import re
import secrets
import time
from pathlib import Path
from typing import Literal

if __package__:
    from .oauth_store import OAuthStore
else:
    from oauth_store import OAuthStore  # type: ignore[no-redef]

ActionKind = Literal["windows", "ssh"]
PROFILE_SAFE = "safe"
PROFILE_ALLOWLIST = "allowlist"
PROFILE_FULL = "full"
DEFAULT_PROFILE = PROFILE_ALLOWLIST
DEFAULT_POLICY_ISSUER = "__default__"
PROFILES = frozenset({PROFILE_SAFE, PROFILE_ALLOWLIST, PROFILE_FULL})
_PROFILE_RANK = {PROFILE_SAFE: 0, PROFILE_ALLOWLIST: 1, PROFILE_FULL: 2}
MAX_RULES = 24
MAX_RULE_SIZE = 512
MAX_FULL_COMMAND_SIZE = 65536  # transport/resource bound, not a command allowlist
DEFAULT_WINDOWS_ALLOWLIST = ("ls", "pwd", "dir", "echo", "whoami", "ipconfig", "systeminfo")
_SSH_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,251}$")


def _parse_rules(text: str, *, host: bool = False) -> tuple[str, ...]:
    """Exact, per-line entries only. No wildcard host or command grants."""
    if not isinstance(text, str) or len(text) > MAX_RULES * MAX_RULE_SIZE:
        raise ValueError("Invalid allowlist")
    rules: list[str] = []
    for line in text.splitlines():
        rule = line.strip()
        if not rule:
            continue
        if len(rule) > MAX_RULE_SIZE or any(ch in rule for ch in ("\x00", "\r", "\t")):
            raise ValueError("Invalid allowlist entry")
        if "*" in rule or "?" in rule:
            raise ValueError("Wildcards are forbidden in allowlist")
        if host and not _SSH_HOST_RE.fullmatch(rule):
            raise ValueError("SSH hosts must be exact hostnames or aliases")
        if rule not in rules:
            rules.append(rule)
        if len(rules) > MAX_RULES:
            raise ValueError("Too many allowlist entries")
    return tuple(rules)


def windows_whitelisted(command: str, entries: tuple[str, ...]) -> bool:
    """Exact lines, plus pure (non-shell) echo with arbitrary literal text."""
    normalized = command.strip()
    if normalized in entries:
        return True
    return "echo" in entries and normalized.lower().startswith("echo ") and len(normalized) <= MAX_RULE_SIZE


class ExecutionApprovals:
    """Encrypted SQLite execution policy, per-client allowlists, and temporary grants."""

    def __init__(self, store: OAuthStore, *, default_profile: str | None = None) -> None:
        self.store = store
        with store._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS exec_policy(
                    issuer TEXT PRIMARY KEY,
                    encrypted BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS exec_client_profiles(
                    issuer TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    encrypted BLOB NOT NULL,
                    PRIMARY KEY(issuer,client_id)
                );
                DROP TABLE IF EXISTS exec_grants;
            """)
            template = self._load_template_from_db(db)
            if default_profile is not None:
                initial_profile = default_profile if default_profile in PROFILES else PROFILE_SAFE
            elif template is not None:
                initial_profile = template["profile"]
            else:
                initial_profile = DEFAULT_PROFILE
            initial_windows = list(template["windows"]) if template is not None else list(DEFAULT_WINDOWS_ALLOWLIST)
            initial_hosts = list(template["hosts"]) if template is not None else []
            initial_ssh = list(template["ssh_commands"]) if template is not None else []
            db.execute(
                "INSERT OR IGNORE INTO exec_policy(issuer, encrypted) VALUES (?,?)",
                (
                    store.issuer,
                    store._encrypt({
                        "profile": initial_profile,
                        "windows": initial_windows,
                        "hosts": initial_hosts,
                        "ssh_commands": initial_ssh,
                    }),
                ),
            )
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='exec_requests'").fetchone():
                db.execute("DELETE FROM exec_requests WHERE issuer=?", (store.issuer,))

    def _load_template_from_db(self, db) -> dict | None:
        if self.store.issuer == DEFAULT_POLICY_ISSUER:
            return None
        row = db.execute(
            "SELECT encrypted FROM exec_policy WHERE issuer=?", (DEFAULT_POLICY_ISSUER,)
        ).fetchone()
        if not row:
            return None
        try:
            payload = self.store._decrypt(row[0])
        except Exception:  # noqa: BLE001
            return None
        if not isinstance(payload, dict):
            return None
        prof = payload.get("profile")
        if prof not in PROFILES:
            prof = PROFILE_SAFE
        return {
            "profile": prof,
            "windows": tuple(payload.get("windows", DEFAULT_WINDOWS_ALLOWLIST)),
            "hosts": tuple(payload.get("hosts", ())),
            "ssh_commands": tuple(payload.get("ssh_commands", ())),
        }

    @classmethod
    def default_template(cls, store_path: Path, *, default_profile: str | None = None) -> ExecutionApprovals:
        """Return the issuer-independent template policy used before server start and to seed new issuers."""
        store = OAuthStore(store_path, DEFAULT_POLICY_ISSUER, DEFAULT_POLICY_ISSUER)
        return cls(store, default_profile=default_profile)

    @classmethod
    def save_default_template(cls, store_path: Path, *, profile: str) -> None:
        if profile not in PROFILES:
            raise ValueError("Unknown access scenario")
        tmpl = cls.default_template(store_path, default_profile=profile)
        tmpl.set_profile(profile)

    def policy(self) -> dict:
        with self.store._db() as db:
            row = db.execute(
                "SELECT encrypted FROM exec_policy WHERE issuer=?", (self.store.issuer,)
            ).fetchone()
        if not row:
            return {
                "profile": PROFILE_SAFE,
                "windows": (),
                "hosts": (),
                "ssh_commands": (),
            }
        try:
            payload = self.store._decrypt(row[0])
        except Exception:  # noqa: BLE001
            # Fail closed on corrupted/tampered policy payload.
            return {
                "profile": PROFILE_SAFE,
                "windows": (),
                "hosts": (),
                "ssh_commands": (),
            }
        if not isinstance(payload, dict):
            return {
                "profile": PROFILE_SAFE,
                "windows": (),
                "hosts": (),
                "ssh_commands": (),
            }
        profile = payload.get("profile", PROFILE_SAFE)
        if profile not in PROFILES:
            profile = PROFILE_SAFE
        return {
            "profile": profile,
            "windows": tuple(payload.get("windows", DEFAULT_WINDOWS_ALLOWLIST)),
            "hosts": tuple(payload.get("hosts", ())),
            "ssh_commands": tuple(payload.get("ssh_commands", ())),
        }

    def profile(self) -> str:
        return self.policy()["profile"]

    def emergency_stopped(self) -> bool:
        return bool(self.store.emergency_stop_state().get("active"))

    def profile_for(self, client_id: str) -> str:
        """Return effective profile for an approved client (emergency stop forces safe)."""
        if self.emergency_stopped() or not self.client_approved(client_id):
            return PROFILE_SAFE
        with self.store._db() as db:
            row = db.execute(
                "SELECT encrypted FROM exec_client_profiles WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            ).fetchone()
        if row:
            try:
                stored = self.store._decrypt(row[0]).get("profile")
                base = stored if stored in PROFILES else PROFILE_SAFE
            except Exception:  # noqa: BLE001
                base = PROFILE_SAFE
        else:
            base = self.profile()

        for grant in self.active_temporary_grants(client_id):
            gp = grant.get("profile")
            if gp in PROFILES and _PROFILE_RANK[gp] > _PROFILE_RANK[base]:
                base = gp
        return base

    def set_client_profile(self, client_id: str, profile: str) -> None:
        """Called exclusively from the local GUI, never an exposed MCP route."""
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ValueError("Unknown access scenario")
        if not isinstance(client_id, str) or not client_id or client_id == "mcp-app-user":
            raise ValueError("Invalid OAuth client")
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=? AND approved_at IS NOT NULL",
                (self.store.issuer, client_id),
            ).fetchone():
                raise ValueError("Cannot assign access to unapproved or revoked client")
            db.execute(
                "INSERT OR REPLACE INTO exec_client_profiles (issuer,client_id,encrypted) VALUES (?,?,?)",
                (self.store.issuer, client_id, self.store._encrypt({"profile": profile})),
            )
            if profile == PROFILE_SAFE:
                db.execute(
                    "DELETE FROM exec_temp_grants WHERE issuer=? AND client_id=?",
                    (self.store.issuer, client_id),
                )

    def client_profiles(self) -> dict[str, str]:
        """Return mapping of client_id -> overridden profile for the active issuer."""
        out: dict[str, str] = {}
        with self.store._db() as db:
            rows = db.execute(
                "SELECT client_id, encrypted FROM exec_client_profiles WHERE issuer=?",
                (self.store.issuer,),
            ).fetchall()
        for row in rows:
            cid = str(row[0] or "")
            if not cid:
                continue
            try:
                stored = self.store._decrypt(row[1]).get("profile")
            except Exception:  # noqa: BLE001
                stored = PROFILE_SAFE
            out[cid] = stored if stored in PROFILES else PROFILE_SAFE
        return out

    def clear_client_profile(self, client_id: str) -> bool:
        """Remove any explicit per-client profile override so global default applies."""
        if not isinstance(client_id, str) or not client_id:
            return False
        with self.store._db() as db:
            cur = db.execute(
                "DELETE FROM exec_client_profiles WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            )
            return cur.rowcount > 0

    def client_allowlist(self, client_id: str) -> dict | None:
        with self.store._db() as db:
            row = db.execute(
                "SELECT encrypted FROM exec_client_allowlists WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            ).fetchone()
        if not row:
            return None
        payload = self.store._decrypt(row[0])
        return {
            "windows": tuple(payload.get("windows", ())),
            "hosts": tuple(payload.get("hosts", ())),
            "ssh_commands": tuple(payload.get("ssh_commands", ())),
        }

    def set_client_allowlist(
        self, client_id: str, *, windows: str, hosts: str, ssh_commands: str
    ) -> None:
        if not self.client_approved(client_id):
            raise ValueError("Cannot assign allowlist to unapproved or revoked client")
        payload = {
            "windows": _parse_rules(windows),
            "hosts": _parse_rules(hosts, host=True),
            "ssh_commands": _parse_rules(ssh_commands),
        }
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO exec_client_allowlists (issuer,client_id,encrypted) VALUES (?,?,?)",
                (self.store.issuer, client_id, self.store._encrypt(payload)),
            )

    def clear_client_allowlist(self, client_id: str) -> bool:
        with self.store._db() as db:
            cur = db.execute(
                "DELETE FROM exec_client_allowlists WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            )
            return cur.rowcount > 0

    def effective_policy_for(self, client_id: str) -> dict:
        base = self.policy()
        custom = self.client_allowlist(client_id)
        if custom is None:
            return {
                **base,
                "profile": self.profile_for(client_id),
            }
        return {
            "profile": self.profile_for(client_id),
            "windows": custom["windows"],
            "hosts": custom["hosts"],
            "ssh_commands": custom["ssh_commands"],
        }

    def grant_temporary_access(
        self,
        client_id: str,
        *,
        profile: str | None = None,
        tool_names: tuple[str, ...] = (),
        windows_commands: tuple[str, ...] = (),
        ssh_hosts: tuple[str, ...] = (),
        ssh_commands: tuple[str, ...] = (),
        ttl_seconds: int = 900,
        reason: str = "",
    ) -> str:
        """Issue an encrypted time-bounded grant for an approved OAuth client."""
        if not self.client_approved(client_id):
            raise ValueError("Cannot issue temporary grant to unapproved client")
        if profile is not None and profile not in PROFILES:
            raise ValueError("Invalid temporary grant profile")
        ttl = max(1, min(int(ttl_seconds), 86400))
        grant_id = secrets.token_hex(8)
        now = int(time.time())
        expires_at = now + ttl
        payload = {
            "profile": profile,
            "tool_names": list(tool_names),
            "windows_commands": list(_parse_rules("\n".join(windows_commands))),
            "ssh_hosts": list(_parse_rules("\n".join(ssh_hosts), host=True)),
            "ssh_commands": list(_parse_rules("\n".join(ssh_commands))),
            "reason": str(reason)[:200],
            "created_at": now,
            "expires_at": expires_at,
        }
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT INTO exec_temp_grants (grant_id,issuer,client_id,encrypted,expires_at) "
                "VALUES (?,?,?,?,?)",
                (grant_id, self.store.issuer, client_id, self.store._encrypt(payload), expires_at),
            )
        return grant_id

    def active_temporary_grants(self, client_id: str) -> list[dict]:
        now = int(time.time())
        with self.store._db() as db:
            rows = db.execute(
                "SELECT grant_id, encrypted, expires_at FROM exec_temp_grants "
                "WHERE issuer=? AND client_id=? AND expires_at>=?",
                (self.store.issuer, client_id, now),
            ).fetchall()
        grants: list[dict] = []
        for grant_id, enc, expires_at in rows:
            data = self.store._decrypt(enc)
            data["grant_id"] = grant_id
            data["expires_at"] = expires_at
            grants.append(data)
        return grants

    def revoke_temporary_grant(self, grant_id: str) -> bool:
        with self.store._db() as db:
            cur = db.execute(
                "DELETE FROM exec_temp_grants WHERE issuer=? AND grant_id=?",
                (self.store.issuer, grant_id),
            )
            return cur.rowcount > 0

    def revoke_client_temporary_grants(self, client_id: str) -> int:
        with self.store._db() as db:
            cur = db.execute(
                "DELETE FROM exec_temp_grants WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            )
            return cur.rowcount

    def prune_expired_grants(self) -> int:
        with self.store._db() as db:
            cur = db.execute(
                "DELETE FROM exec_temp_grants WHERE issuer=? AND expires_at<?",
                (self.store.issuer, int(time.time())),
            )
            return cur.rowcount

    def _save(self, policy: dict) -> None:
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                "INSERT OR REPLACE INTO exec_policy(issuer,encrypted) VALUES (?,?)",
                (self.store.issuer, self.store._encrypt(policy)),
            )
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='exec_requests'").fetchone():
                db.execute("DELETE FROM exec_requests WHERE issuer=?", (self.store.issuer,))

    def set_profile(self, profile: str) -> None:
        """Local GUI only. Full access requires an explicit UI warning."""
        if profile not in PROFILES:
            raise ValueError("Unknown access scenario")
        policy = self.policy()
        policy["profile"] = profile
        self._save(policy)

    def set_policy(self, *, windows: str, hosts: str, ssh_commands: str) -> None:
        """Owner-edited exact allowlists; profile remains unchanged."""
        policy = self.policy()
        policy.update({
            "windows": _parse_rules(windows),
            "hosts": _parse_rules(hosts, host=True),
            "ssh_commands": _parse_rules(ssh_commands),
        })
        self._save(policy)

    def client_approved(self, client_id: str) -> bool:
        if not isinstance(client_id, str) or not client_id or client_id == "mcp-app-user":
            return False
        with self.store._db() as db:
            return bool(
                db.execute(
                    "SELECT 1 FROM clients WHERE issuer=? AND client_id=? AND approved_at IS NOT NULL",
                    (self.store.issuer, client_id),
                ).fetchone()
            )

    def can_request(
        self,
        client_id: str,
        kind: ActionKind,
        *,
        command: str,
        host: str = "",
        user: str = "",
        port: int = 22,
        expected_profile: str | None = None,
    ) -> bool:
        if self.emergency_stopped():
            return False
        if kind not in ("windows", "ssh") or not self.client_approved(client_id):
            return False
        if (
            not isinstance(command, str)
            or not command.strip()
            or "\x00" in command
            or len(command) > MAX_FULL_COMMAND_SIZE
        ):
            return False
        if type(port) is not int or not (1 <= port <= 65535) or not isinstance(user, str):
            return False
        if len(user) > 64 or any(ch in user for ch in ("/", "\\", " ", "@", "\x00")):
            return False
        if kind == "windows" and (host or user):
            return False
        if kind == "ssh" and (not isinstance(host, str) or not _SSH_HOST_RE.fullmatch(host)):
            return False

        profile = self.profile_for(client_id)
        if expected_profile is not None and expected_profile != profile:
            return False

        # Temporary command grants can authorize a specific command even if base profile is safe/allowlist.
        if len(command) <= MAX_RULE_SIZE:
            for grant in self.active_temporary_grants(client_id):
                if kind == "windows" and windows_whitelisted(
                    command, tuple(grant.get("windows_commands", ()))
                ):
                    return True
                if (
                    kind == "ssh"
                    and host in tuple(grant.get("ssh_hosts", ()))
                    and command.strip() in tuple(grant.get("ssh_commands", ()))
                ):
                    return True

        if profile == PROFILE_SAFE:
            return False
        if profile == PROFILE_FULL:
            return True
        if len(command) > MAX_RULE_SIZE:
            return False
        policy = self.effective_policy_for(client_id)
        if kind == "windows":
            return windows_whitelisted(command, policy["windows"])
        return host in policy["hosts"] and command.strip() in policy["ssh_commands"]
