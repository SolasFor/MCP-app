"""Backwards-compatible ManagedServers facade backed by Stage 6 ServerManager.

Preserves existing `ManagedServers(path)` contracts and legacy `managed_servers.json`
schema compatibility while delegating process lifecycle, secret refs, readiness,
dependencies, metrics, and logs to `backend.servers`.
"""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

from app.core.redaction import SecretRedactor
from app.core.secret_store import SecretStore
from backend.process_runner import ProcessRunner
from backend.servers.manager import ServerManager
from backend.servers.models import ServerProfile
from backend.servers.store import ServerConfigStore


class ManagedServers:
    """Compatibility wrapper over `ServerConfigStore` and `ServerManager`."""

    def __init__(
        self,
        path: Path,
        runner: ProcessRunner | None = None,
        *,
        redactor: SecretRedactor | None = None,
        task_store: Any = None,
        secret_store: SecretStore | None = None,
        auth_rechecker: Callable[[str, ServerProfile], None] | None = None,
    ) -> None:
        self.path = Path(path)
        self.store = ServerConfigStore(self.path, secret_store=secret_store)
        self.manager = ServerManager(
            self.store,
            runner=runner,
            redactor=redactor,
            task_store=task_store,
            auth_rechecker=auth_rechecker,
        )

    @staticmethod
    def _to_legacy_dict(item: dict[str, Any]) -> dict[str, Any]:
        return {
            "name": item["name"],
            "running": bool(item.get("running", False)),
            "exit_code": item.get("exit_code"),
            "lifecycle": item.get("lifecycle", "controlled"),
        }

    def list(self, client_id: str) -> list[dict[str, Any]]:
        """List configured servers visible in legacy Full mode."""
        items = self.manager.list_servers(client_id=client_id, client_profile="full")
        return [self._to_legacy_dict(item) for item in items]

    def start(self, client_id: str, name: str) -> dict[str, Any]:
        """Start a configured server for `client_id` preserving ValueError compatibility."""
        try:
            item = self.manager.start_server(
                name,
                client_id=client_id,
                client_profile="full",
                start_dependencies=True,
                wait_readiness=False,
            )
            return self._to_legacy_dict(item)
        except PermissionError as exc:
            raise ValueError(str(exc)) from exc

    def stop(self, client_id: str, name: str) -> dict[str, Any]:
        """Stop an owned controlled server or return honest independent status."""
        try:
            item = self.manager.stop_server(
                name,
                client_id=client_id,
                client_profile="full",
                grace_seconds=2.0,
            )
            return self._to_legacy_dict(item)
        except PermissionError as exc:
            raise ValueError(str(exc)) from exc

    def close(self) -> None:
        self.manager.close()
