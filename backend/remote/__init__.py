"""Stage 10 Remote Management package: devices registry, strict SSH/SFTP, jobs & metrics."""
from __future__ import annotations

from backend.remote.manager import RemoteManager
from backend.remote.models import (
    DEFAULT_SFTP_MAX_BYTES,
    DevicePermissions,
    DeviceProfile,
    RemoteJobRecord,
    validate_device_id,
    validate_remote_posix_path,
    validate_service_name,
)
from backend.remote.ssh_client import SSHConnectionError, SSHConnectionManager
from backend.remote.store import DeviceStore, import_ssh_config

__all__ = [
    "DEFAULT_SFTP_MAX_BYTES",
    "DevicePermissions",
    "DeviceProfile",
    "DeviceStore",
    "RemoteJobRecord",
    "RemoteManager",
    "SSHConnectionError",
    "SSHConnectionManager",
    "import_ssh_config",
    "validate_device_id",
    "validate_remote_posix_path",
    "validate_service_name",
]
