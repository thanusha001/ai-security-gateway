"""Rate limiting (sliding window, per user or per client IP).

Configurable via RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW_SECONDS. Rate-limit
events are recorded to the rate_limit_events table by the caller (API layer)
so denials are auditable. For a single-process local deployment an in-memory
limiter is sufficient and documented as a limitation for multi-worker setups.
"""
from __future__ import annotations

import time
from collections import defaultdict, deque

from app.core.config import settings


class SlidingWindowLimiter:
    def __init__(self, max_requests: int, window_seconds: int) -> None:
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> tuple[bool, int, int]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        window_start = now - self.window_seconds
        hits = self._hits[key]
        while hits and hits[0] < window_start:
            hits.popleft()
        if len(hits) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - hits[0])) + 1
            return False, 0, max(1, retry_after)
        hits.append(now)
        return True, self.max_requests - len(hits), 0


chat_limiter = SlidingWindowLimiter(settings.rate_limit_requests, settings.rate_limit_window_seconds)
upload_limiter = SlidingWindowLimiter(
    settings.rate_limit_upload_requests, settings.rate_limit_upload_window_seconds
)
