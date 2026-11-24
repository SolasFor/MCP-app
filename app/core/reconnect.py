"""Exponential backoff with jitter and stable-uptime reset for service reconnects."""
from __future__ import annotations

import random
import time
from collections.abc import Callable


class BackoffPolicy:
    """Computes bounded exponential backoff delays with symmetric jitter."""

    def __init__(
        self,
        *,
        base_seconds: float = 2.0,
        max_seconds: float = 60.0,
        jitter_ratio: float = 0.25,
        max_attempts: int = 5,
        stable_uptime_seconds: float = 60.0,
    ) -> None:
        self.base_seconds = max(0.1, float(base_seconds))
        self.max_seconds = max(self.base_seconds, float(max_seconds))
        self.jitter_ratio = max(0.0, min(0.9, float(jitter_ratio)))
        self.max_attempts = max(1, int(max_attempts))
        self.stable_uptime_seconds = max(1.0, float(stable_uptime_seconds))

    def next_delay(
        self, attempt: int, rng: Callable[[], float] | None = None
    ) -> float:
        """Return delay in seconds for 1-based `attempt`."""
        n = max(1, int(attempt))
        raw = min(self.base_seconds * (2 ** (n - 1)), self.max_seconds)
        if self.jitter_ratio <= 0.0:
            return raw
        rand_unit = rng() if rng is not None else random.random()
        # Map [0, 1) -> [-jitter_ratio, +jitter_ratio]
        factor = 1.0 + ((2.0 * rand_unit - 1.0) * self.jitter_ratio)
        return max(0.5, min(self.max_seconds, raw * factor))

    def should_reset_attempts(
        self, healthy_since: float | None, now: float | None = None
    ) -> bool:
        if healthy_since is None:
            return False
        current = time.monotonic() if now is None else now
        return (current - healthy_since) > self.stable_uptime_seconds

    def exhausted(self, attempt: int) -> bool:
        return attempt > self.max_attempts
