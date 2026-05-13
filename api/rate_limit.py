"""
Simple in-memory rate limiter — no external dependencies required.
Not suitable for multi-process deployments; use Redis-backed throttling there.
"""

import time
from collections import defaultdict
from typing import Dict, List

from fastapi import HTTPException

_store: Dict[str, List[float]] = defaultdict(list)


def check_rate_limit(key: str, max_calls: int, window_seconds: int) -> None:
    """Raise HTTP 429 if `key` has exceeded `max_calls` within `window_seconds`."""
    now = time.monotonic()
    _store[key] = [t for t in _store[key] if now - t < window_seconds]
    if len(_store[key]) >= max_calls:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded — max {max_calls} requests per {window_seconds}s",
        )
    _store[key].append(now)
