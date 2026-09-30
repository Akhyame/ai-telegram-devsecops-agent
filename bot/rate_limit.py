"""Thread-safe bounded in-memory rate limiting for abuse resistance."""

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(slots=True)
class _RateWindow:
    started_at: float
    request_count: int


class BoundedRateLimiter:
    """Fixed-window limiter with bounded identity state."""

    def __init__(
        self,
        *,
        maximum_requests: int,
        window_seconds: float,
        maximum_entries: int = 1_024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if maximum_requests <= 0 or window_seconds <= 0 or maximum_entries <= 0:
            raise ValueError("Rate limiter configuration is invalid.")

        self._maximum_requests = maximum_requests
        self._window_seconds = window_seconds
        self._maximum_entries = maximum_entries
        self._clock = clock
        self._entries: dict[str, _RateWindow] = {}
        self._lock = threading.RLock()

    def allow(self, identity: str) -> bool:
        """Atomically accept or reject one request for a bounded identity."""

        if not isinstance(identity, str) or not identity or len(identity) > 128:
            return False

        now = self._clock()

        with self._lock:
            self._prune_expired(now)

            window = self._entries.get(identity)

            if window is None:
                if len(self._entries) >= self._maximum_entries:
                    self._evict_oldest()

                self._entries[identity] = _RateWindow(
                    started_at=now,
                    request_count=1,
                )
                return True

            if now - window.started_at >= self._window_seconds:
                window.started_at = now
                window.request_count = 1
                return True

            if window.request_count >= self._maximum_requests:
                return False

            window.request_count += 1
            return True

    @property
    def entry_count(self) -> int:
        """Return current bounded state after expiry pruning."""

        now = self._clock()

        with self._lock:
            self._prune_expired(now)
            return len(self._entries)

    def clear(self) -> None:
        """Clear process-local limiter state."""

        with self._lock:
            self._entries.clear()

    def _prune_expired(self, now: float) -> None:
        expired = [
            identity
            for identity, window in self._entries.items()
            if now - window.started_at >= self._window_seconds
        ]

        for identity in expired:
            self._entries.pop(identity, None)

    def _evict_oldest(self) -> None:
        if not self._entries:
            return

        oldest_identity = min(
            self._entries,
            key=lambda identity: self._entries[identity].started_at,
        )
        self._entries.pop(oldest_identity, None)
