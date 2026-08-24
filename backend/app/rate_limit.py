"""
Minimal in-memory rate limiter for auth endpoints (brute-force protection).

NOTE: this is per-process. Fine for a single backend instance; if you run
multiple workers/replicas behind a load balancer, replace this with a
shared store (e.g. Redis) so limits apply across all of them.
"""
import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request

_attempts: dict[str, deque] = defaultdict(deque)

def rate_limit(request: Request, key_prefix: str, max_attempts: int = 5, window_seconds: int = 60):
    ip = request.client.host if request.client else "unknown"
    key = f"{key_prefix}:{ip}"
    now = time.monotonic()
    bucket = _attempts[key]
    while bucket and now - bucket[0] > window_seconds:
        bucket.popleft()
    if len(bucket) >= max_attempts:
        raise HTTPException(429, "Too many attempts. Please try again later.")
    bucket.append(now)
