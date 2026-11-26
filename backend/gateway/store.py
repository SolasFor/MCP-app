"""Persistent gateway server config store with DPAPI SecretStore isolation and safe import/export."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.secret_store import SecretStore
from app.platform import get_platform
from backend.gateway.models import (
    ISOLATION_SHARED,
    TRANSPORT_SSE,
    TRANSPORT_STDIO,
    TRANSPORT_STREAMABLE_HTTP,
    ImportPreviewItem,
    UpstreamServerProfile,
    normalize_server_id,
)
from backend.gateway.security import detect_untrusted_launcher, looks_like_secret_env_name, validate_upstream_url


def solidworks_mcp_template() -> UpstreamServerProfile:
    """Preset for Windows user-session COM SolidWorks MCP server (requires local owner approval)."""
    return UpstreamServerProfile(
        server_id="solidworks",
        name="SolidWorks MCP (User Session COM)",
        transport=TRANSPORT_STDIO,
        enabled=False,
        autostart=False,
        command="python",
        args=("-m", "solidworks_mcp"),
        cwd="",
        session_isolation=ISOLATION_SHARED,
        min_profile="allowlist",
        timeout_seconds=60.0,
        approved_by_owner=False,
        notes=(
            "Runs inside the interactive Windows user session so SolidWorks COM API stays reachable. "
            "Requires a compatible SolidWorks installation, valid license, and explicit owner verification "
            "before enabling."
        ),
    )


class GatewayConfigStore:
    """Stores upstream MCP server profiles (non-secret JSON) + encrypted SecretStore entries."""

    def __init__(self, config_path: Path, secret_store: SecretStore | None = None) -> None:
        from app.core.atomic_io import try_init_private_dir

        self.path = Path(config_path)
        self._platform = get_platform()
        try_init_private_dir(self.path.parent)
        self.secrets = secret_store or SecretStore(self.path.parent.parent / "secrets")
        self._profiles: dict[str, UpstreamServerProfile] = {}
        self.load()

    def load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._profiles = {}
            return
        if not isinstance(raw, dict):
            self._profiles = {}
            return
        items = raw.get("servers")
        loaded: dict[str, UpstreamServerProfile] = {}
        if isinstance(items, dict):
            for sid, entry in items.items():
                if isinstance(entry, dict):
                    merged = {"server_id": sid, **entry}
                    prof = UpstreamServerProfile.from_dict(merged)
                    if not prof.validate():
                        loaded[prof.server_id] = prof
        self._profiles = loaded

    def save(self) -> None:
        from app.core.atomic_io import atomic_write_json

        payload = {
            "version": 1,
            "servers": {sid: prof.to_dict() for sid, prof in sorted(self._profiles.items())},
        }
        atomic_write_json(self.path, payload, indent=2, restrict_acl=True)

    def list_profiles(self) -> list[UpstreamServerProfile]:
        return [self._profiles[k] for k in sorted(self._profiles)]

    def get(self, server_id: str) -> UpstreamServerProfile | None:
        return self._profiles.get(server_id)

    def upsert(
        self,
        profile: UpstreamServerProfile,
        *,
        secret_env: dict[str, str] | None = None,
        bearer_token: str | None = None,
        secret_headers: dict[str, str] | None = None,
        self_urls: tuple[str, ...] = (),
    ) -> list[str]:
        errors = profile.validate()
        if profile.transport != TRANSPORT_STDIO and not errors:
            try:
                validate_upstream_url(
                    profile.url,
                    allow_local_endpoint=profile.allow_local_endpoint,
                    self_urls=self_urls,
                )
            except ValueError as exc:
                errors.append(str(exc))
        if errors:
            return errors

        env_refs = dict(profile.env_secret_refs)
        for key, value in (secret_env or {}).items():
            clean = value.strip()
            if clean:
                sec_key = f"gateway_{profile.server_id}_env_{key}"
                self.secrets.set_secret("api", sec_key, clean)
                env_refs[key] = SecretStore.secret_ref("api", sec_key)

        auth_ref = profile.auth_secret_ref
        if bearer_token is not None:
            clean_tok = bearer_token.strip()
            if clean_tok:
                sec_key = f"gateway_{profile.server_id}_bearer"
                self.secrets.set_secret("external_oauth", sec_key, clean_tok)
                auth_ref = SecretStore.secret_ref("external_oauth", sec_key)
            else:
                auth_ref = ""

        hdr_refs = dict(profile.headers_secret_refs)
        for h_name, h_val in (secret_headers or {}).items():
            clean_hv = h_val.strip()
            if clean_hv:
                sec_key = f"gateway_{profile.server_id}_hdr_{h_name}"
                self.secrets.set_secret("api", sec_key, clean_hv)
                hdr_refs[h_name] = SecretStore.secret_ref("api", sec_key)

        updated = UpstreamServerProfile.from_dict(
            {
                **profile.to_dict(),
                "env_secret_refs": env_refs,
                "auth_secret_ref": auth_ref,
                "headers_secret_refs": hdr_refs,
            }
        )
        self._profiles[updated.server_id] = updated
        self.save()
        return []

    def delete(self, server_id: str) -> bool:
        if server_id not in self._profiles:
            return False
        del self._profiles[server_id]
        self.save()
        return True

    def resolve_runtime_secrets(self, profile: UpstreamServerProfile) -> tuple[dict[str, str], dict[str, str]]:
        """Resolve encrypted env vars and HTTP headers for an authorized upstream connection."""
        env_out = dict(profile.env)
        for key, ref in profile.env_secret_refs.items():
            val = self.secrets.resolve_ref(ref)
            if val:
                env_out[key] = val

        hdrs_out: dict[str, str] = {}
        if profile.auth_mode == "bearer" and profile.auth_secret_ref:
            tok = self.secrets.resolve_ref(profile.auth_secret_ref)
            if tok:
                hdrs_out["Authorization"] = f"Bearer {tok}"
        for h_name, ref in profile.headers_secret_refs.items():
            val = self.secrets.resolve_ref(ref)
            if val:
                hdrs_out[h_name] = val
        return env_out, hdrs_out

    def collect_secret_values(self) -> list[str]:
        vals: list[str] = []
        for prof in self._profiles.values():
            refs = [prof.auth_secret_ref, *prof.env_secret_refs.values(), *prof.headers_secret_refs.values()]
            for ref in refs:
                if not ref:
                    continue
                try:
                    val = self.secrets.resolve_ref(ref)
                except (OSError, ValueError, RuntimeError):
                    val = None
                if val:
                    vals.append(val)
        return vals

    def preview_standard_mcp_json(self, raw_json: str) -> list[ImportPreviewItem]:
        """Parse Claude/Cursor/VS Code `mcpServers` JSON without trusting or enabling servers yet."""
        data = json.loads(raw_json)
        if not isinstance(data, dict):
            raise ValueError("JSON root must be an object.")
        servers_map = data.get("mcpServers") or data.get("servers")
        if not isinstance(servers_map, dict):
            raise ValueError("Expected `mcpServers` or `servers` object in MCP configuration.")

        previews: list[ImportPreviewItem] = []
        for raw_id, entry in servers_map.items():
            if not isinstance(entry, dict):
                continue
            sid = normalize_server_id(str(raw_id))
            warnings: list[str] = []
            inline_secrets: dict[str, str] = {}
            plain_env: dict[str, str] = {}

            raw_url = str(entry.get("url") or "").strip()
            raw_type = str(entry.get("transport") or entry.get("type") or "").strip().lower()
            if raw_url:
                transport = TRANSPORT_SSE if raw_type == "sse" else TRANSPORT_STREAMABLE_HTTP
                command = ""
                args: tuple[str, ...] = ()
            else:
                transport = TRANSPORT_STDIO
                command = str(entry.get("command") or "").strip()
                args = tuple(str(x) for x in (entry.get("args") or ()))
                if detect_untrusted_launcher(command, args):
                    warnings.append(f"Dynamic launcher `{command}` requires explicit owner review before running.")

            for env_k, env_v in (entry.get("env") or {}).items():
                k_str, v_str = str(env_k), str(env_v)
                if looks_like_secret_env_name(k_str):
                    inline_secrets[k_str] = v_str
                    warnings.append(f"Inline secret env `{k_str}` will move into encrypted SecretStore.")
                else:
                    plain_env[k_str] = v_str

            profile = UpstreamServerProfile(
                server_id=sid,
                name=str(entry.get("name") or raw_id),
                transport=transport,
                enabled=False,
                autostart=False,
                command=command,
                args=args,
                cwd=str(entry.get("cwd") or ""),
                env=plain_env,
                url=raw_url,
                allow_local_endpoint=raw_url.startswith("http://127.0.0.1") or raw_url.startswith("http://localhost"),
                min_profile="allowlist",
                approved_by_owner=False,
            )
            previews.append(
                ImportPreviewItem(profile=profile, inline_secrets=inline_secrets, warnings=tuple(warnings))
            )
        return previews

    def commit_import(
        self,
        items: list[ImportPreviewItem],
        *,
        approved_by_owner: bool,
        enable_imported: bool = True,
    ) -> list[str]:
        if not approved_by_owner:
            raise PermissionError("Owner confirmation is required before importing upstream MCP servers.")
        imported: list[str] = []
        for item in items:
            prof = UpstreamServerProfile.from_dict(
                {
                    **item.profile.to_dict(),
                    "approved_by_owner": True,
                    "enabled": bool(enable_imported),
                }
            )
            errors = self.upsert(prof, secret_env=item.inline_secrets)
            if not errors:
                imported.append(prof.server_id)
        return imported

    def export_redacted_json(self) -> str:
        """Export profiles without plaintext secrets (preserving only opaque secret:// refs)."""
        exported: dict[str, Any] = {}
        for prof in self.list_profiles():
            d = prof.to_dict()
            d["env"] = dict(prof.env)
            exported[prof.server_id] = d
        return json.dumps({"version": 1, "servers": exported}, indent=2, ensure_ascii=False)
