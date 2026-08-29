import hashlib
import math
import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    reset_at: int
    retry_after: int


class FixedWindowRateLimiter:
    """Thread-safe, process-local fixed-window rate limiter."""

    def __init__(self) -> None:
        self._entries: dict[
            tuple[str, str],
            tuple[int, int],
        ] = {}
        self._lock = threading.Lock()
        self._checks = 0

    def check(
        self,
        *,
        policy: str,
        subject: str,
        limit: int,
        window_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        if limit < 1:
            raise ValueError("Rate limit must be positive.")

        if window_seconds < 1:
            raise ValueError("Rate limit window must be positive.")

        current_time = time.time() if now is None else now
        window_start = (
            int(current_time) // window_seconds
        ) * window_seconds
        reset_at = window_start + window_seconds
        key = (policy, subject)

        with self._lock:
            stored_window, count = self._entries.get(
                key,
                (window_start, 0),
            )

            if stored_window != window_start:
                count = 0

            allowed = count < limit

            if allowed:
                count += 1
                self._entries[key] = (window_start, count)

            self._checks += 1

            if self._checks % 1_024 == 0:
                self._remove_expired(window_start)

        retry_after = max(
            1,
            math.ceil(reset_at - current_time),
        )

        return RateLimitDecision(
            allowed=allowed,
            limit=limit,
            remaining=max(0, limit - count),
            reset_at=reset_at,
            retry_after=retry_after,
        )

    def _remove_expired(self, current_window: int) -> None:
        expired = [
            key
            for key, (window_start, _) in self._entries.items()
            if window_start < current_window
        ]

        for key in expired:
            del self._entries[key]

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._checks = 0


def rate_limit_subject(
    *,
    credential: str | None,
    client_host: str | None,
) -> str:
    if credential:
        source = f"credential:{credential}"
    else:
        source = f"anonymous:{client_host or 'unknown'}"

    return hashlib.sha256(source.encode("utf-8")).hexdigest()


__all__ = [
    "FixedWindowRateLimiter",
    "RateLimitDecision",
    "rate_limit_subject",
]
