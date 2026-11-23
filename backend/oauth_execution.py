"""Three owner-selected execution profiles for OAuth MCP clients.

safe (default): no command/SSH tools.
allowlist: Windows command lines and SSH host+commands must match exact owner
           entries; no per-call confirmation.
full: approved OAuth clients can run Windows shell/SSH commands immediately.

The global default and per-client profile overrides are stored encrypted in
SQLite and reread for each tool discovery and invocation. No remote admin
route can mutate permissions.
"""
from __future__ import annotations

import re
from typing import Literal

try:
    from .oauth_store import OAuthStore
except ImportError:
    from oauth_store import OAuthStore

ActionKind = Literal["windows", "ssh"]
PROFILE_SAFE = "safe"
PROFILE_ALLOWLIST = "allowlist"
PROFILE_FULL = "full"
PROFILES = frozenset({PROFILE_SAFE, PROFILE_ALLOWLIST, PROFILE_FULL})
MAX_RULES = 24
MAX_RULE_SIZE = 512
# Standard Windows read-only helpers. These are preloaded as a policy,
# but the OAuth execution profile itself always defaults to "safe".
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
    """Retained class name for compatibility with existing GUI/backend imports.

    No approvals or tickets are created in any of the three scenarios.
    """

    def __init__(self, store: OAuthStore) -> None:
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
            # Seed new installations once, so the GUI's allowlist is populated
            # immediately. Never overwrite an existing owner-edited policy:
            # users may intentionally have removed or disabled commands.
            db.execute(
                "INSERT OR IGNORE INTO exec_policy(issuer, encrypted) VALUES (?,?)",
                (store.issuer, store._encrypt({
                    "profile": PROFILE_SAFE,
                    "windows": list(DEFAULT_WINDOWS_ALLOWLIST),
                    "hosts": [], "ssh_commands": [],
                })),
            )
            # Old short-lived approval tickets cannot authorize anything here.
            if db.execute("SELECT 1 FROM sqlite_master WHERE name='exec_requests'").fetchone():
                db.execute("DELETE FROM exec_requests WHERE issuer=?", (store.issuer,))

    def policy(self) -> dict:
        with self.store._db() as db:
            row = db.execute("SELECT encrypted FROM exec_policy WHERE issuer=?",
                             (self.store.issuer,)).fetchone()
        if not row:
            return {
                "profile": PROFILE_SAFE, "windows": DEFAULT_WINDOWS_ALLOWLIST,
                "hosts": (), "ssh_commands": (),
            }
        payload = self.store._decrypt(row[0])
        profile = payload.get("profile", PROFILE_SAFE)
        if profile not in PROFILES:
            profile = PROFILE_SAFE
        # Existing records from earlier builds contain lists but no profile:
        # never silently convert them to command execution privileges.
        return {
            "profile": profile,
            "windows": tuple(payload.get("windows", DEFAULT_WINDOWS_ALLOWLIST)),
            "hosts": tuple(payload.get("hosts", ())),
            "ssh_commands": tuple(payload.get("ssh_commands", ())),
        }

    def profile(self) -> str:
        return self.policy()["profile"]

    def profile_for(self, client_id: str) -> str:
        """Return this approved client's explicit profile, else the global default.

        A revoked, unapproved or unknown client can never receive privileges.
        The encrypted SQLite row is read anew for every list and call, allowing
        the owner to downgrade access immediately without reconnecting.
        """
        if not self.client_approved(client_id):
            return PROFILE_SAFE
        with self.store._db() as db:
            row = db.execute(
                "SELECT encrypted FROM exec_client_profiles "
                "WHERE issuer=? AND client_id=?",
                (self.store.issuer, client_id),
            ).fetchone()
        if row:
            stored = self.store._decrypt(row[0]).get("profile")
            return stored if stored in PROFILES else PROFILE_SAFE
        return self.profile()

    def set_client_profile(self, client_id: str, profile: str) -> None:
        """Called exclusively from the local GUI, never an exposed MCP route."""
        if not isinstance(profile, str) or profile not in PROFILES:
            raise ValueError("Unknown access scenario")
        if not isinstance(client_id, str) or not client_id or client_id == "mcp-app-user":
            raise ValueError("Invalid OAuth client")
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=? "
                "AND approved_at IS NOT NULL",
                (self.store.issuer, client_id),
            ).fetchone():
                raise ValueError("Cannot assign access to unapproved or revoked client")
            db.execute(
                "INSERT OR REPLACE INTO exec_client_profiles "
                "(issuer,client_id,encrypted) VALUES (?,?,?)",
                (self.store.issuer, client_id,
                 self.store._encrypt({"profile": profile})),
            )

    def _save(self, policy: dict) -> None:
        with self.store._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR REPLACE INTO exec_policy(issuer,encrypted) VALUES (?,?)",
                       (self.store.issuer, self.store._encrypt(policy)))
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
            return bool(db.execute(
                "SELECT 1 FROM clients WHERE issuer=? AND client_id=? AND approved_at IS NOT NULL",
                (self.store.issuer, client_id),
            ).fetchone())

    def can_request(
        self, client_id: str, kind: ActionKind, *, command: str,
        host: str = "", user: str = "", port: int = 22,
    ) -> bool:
        if kind not in ("windows", "ssh") or not self.client_approved(client_id):
            return False
        if not isinstance(command, str) or not command.strip() or len(command) > MAX_RULE_SIZE:
            return False
        if type(port) is not int or not (1 <= port <= 65535) or not isinstance(user, str):
            return False
        if len(user) > 64 or any(ch in user for ch in ("/", "\\", " ", "@", "\x00")):
            return False
        if kind == "windows" and (host or user):
            return False
        if kind == "ssh" and (not isinstance(host, str) or not _SSH_HOST_RE.fullmatch(host)):
            return False
        policy = self.policy()
        profile = self.profile_for(client_id)
        if profile == PROFILE_SAFE:
            return False
        if profile == PROFILE_FULL:
            return True
        if kind == "windows":
            return windows_whitelisted(command, policy["windows"])
        return host in policy["hosts"] and command.strip() in policy["ssh_commands"]
