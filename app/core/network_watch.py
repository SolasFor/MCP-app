"""Sleep/wake and network-interface change detection (Qt monitor + pure helpers)."""
from __future__ import annotations

import time

import psutil
from PyQt6.QtCore import QObject, QTimer, pyqtSignal


def detect_sleep_gap(
    last_monotonic: float,
    last_wall: float,
    now_monotonic: float,
    now_wall: float,
    threshold_s: float = 20.0,
) -> float | None:
    """Return estimated sleep/suspend duration if a wake gap occurred, else None."""
    wall_delta = now_wall - last_wall
    mono_delta = max(0.0, now_monotonic - last_monotonic)
    # On Windows, monotonic clock may freeze or lag behind wall clock during sleep,
    # or the timer interval itself jumps significantly past threshold_s.
    sleep_gap = wall_delta - mono_delta
    if sleep_gap >= threshold_s:
        return sleep_gap
    if mono_delta >= threshold_s * 3.0 and wall_delta >= threshold_s * 3.0:
        return mono_delta
    return None


def network_interface_fingerprint() -> tuple[tuple[str, bool, tuple[str, ...]], ...]:
    """Deterministic snapshot of active non-loopback network interfaces and IPs."""
    try:
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
    except psutil.Error:
        return ()

    snapshot: list[tuple[str, bool, tuple[str, ...]]] = []
    for name in sorted(addrs):
        low = name.lower()
        if "loopback" in low or low == "lo":
            continue
        is_up = bool(stats.get(name).isup) if name in stats else False
        ips = sorted(
            {
                addr.address
                for addr in addrs[name]
                if getattr(addr, "address", None)
                and not str(addr.address).startswith("127.")
                and str(addr.address) != "::1"
            }
        )
        if is_up or ips:
            snapshot.append((name, is_up, tuple(ips)))
    return tuple(snapshot)


class SystemResilienceMonitor(QObject):
    """Polls lightly in GUI loop to detect system sleep/wake and network changes."""

    system_resumed = pyqtSignal(float)
    network_changed = pyqtSignal(str)

    def __init__(self, interval_ms: int = 5000, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._interval_ms = max(1000, int(interval_ms))
        self._timer = QTimer(self)
        self._timer.setInterval(self._interval_ms)
        self._timer.timeout.connect(self._poll)
        self._last_mono = time.monotonic()
        self._last_wall = time.time()
        self._last_net = network_interface_fingerprint()

    def start(self) -> None:
        self._last_mono = time.monotonic()
        self._last_wall = time.time()
        self._last_net = network_interface_fingerprint()
        if not self._timer.isActive():
            self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def _poll(self) -> None:
        now_mono = time.monotonic()
        now_wall = time.time()
        gap = detect_sleep_gap(self._last_mono, self._last_wall, now_mono, now_wall)
        self._last_mono = now_mono
        self._last_wall = now_wall
        if gap is not None:
            self.system_resumed.emit(gap)

        current_net = network_interface_fingerprint()
        if current_net != self._last_net:
            self._last_net = current_net
            summary = ", ".join(
                f"{name}({'up' if up else 'down'})" for name, up, _ips in current_net
            ) or "no-active-interfaces"
            self.network_changed.emit(summary)
