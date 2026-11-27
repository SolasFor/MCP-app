"""MCP-app Workspaces package (v0.9.5)."""
from __future__ import annotations

from backend.workspaces.history import WorkspaceHistory
from backend.workspaces.manager import WorkspaceManager
from backend.workspaces.server_links import WorkspaceServerCoordinator, WorkspaceServersSnapshot
from backend.workspaces.models import (
    MAX_HISTORY_SNAPSHOTS,
    MAX_READ_BYTES,
    MAX_SEARCH_MATCHES,
    MAX_TREE_ENTRIES,
    MAX_WORKSPACES,
    MAX_WRITE_BYTES,
    PERMISSION_FLAGS,
    SCHEMA_VERSION,
    WORKSPACE_MIN_PROFILES,
    WorkspacePermissions,
    WorkspaceProfile,
)
from backend.workspaces.path_security import (
    FileVersionConflictError,
    GitIgnoreMatcher,
    PathSecurityError,
    atomic_write_verified,
    canonical_workspace_root,
    is_reparse_or_link,
    read_verified_bytes,
    resolve_workspace_path,
)
from backend.workspaces.store import WorkspaceStore, detect_workspace_metadata

__all__ = [
    "FileVersionConflictError",
    "GitIgnoreMatcher",
    "MAX_HISTORY_SNAPSHOTS",
    "MAX_READ_BYTES",
    "MAX_SEARCH_MATCHES",
    "MAX_TREE_ENTRIES",
    "MAX_WORKSPACES",
    "MAX_WRITE_BYTES",
    "PERMISSION_FLAGS",
    "PathSecurityError",
    "SCHEMA_VERSION",
    "WORKSPACE_MIN_PROFILES",
    "WorkspaceHistory",
    "WorkspaceManager",
    "WorkspacePermissions",
    "WorkspaceProfile",
    "WorkspaceServerCoordinator",
    "WorkspaceServersSnapshot",
    "WorkspaceStore",
    "atomic_write_verified",
    "canonical_workspace_root",
    "detect_workspace_metadata",
    "is_reparse_or_link",
    "read_verified_bytes",
    "resolve_workspace_path",
]
