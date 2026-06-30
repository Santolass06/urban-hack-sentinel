"""
API middleware for Sprint 8A hardening.

- Security headers (HSTS, CSP, nosniff, etc.)
- Optional IP allowlist for sensitive endpoints
- Simple in-memory rate limiting per client IP
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Callable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from urban_hs.core.config import get_config

_SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add a baseline set of security response headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        for header, value in _SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        return response


class IPAllowlistMiddleware(BaseHTTPMiddleware):
    """Allowlist-only access when enabled in config."""

    def __init__(self, app, *, enabled: bool = False, allowed_ips: Optional[list[str]] = None) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.allowed_ips = set(allowed_ips or [])

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled or not self.allowed_ips:
            return await call_next(request)
        client = request.client
        if client is None or client.host not in self.allowed_ips:
            return Response("Forbidden", status_code=403)
        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Basic token-bucket style rate limiter per client IP."""

    def __init__(
        self,
        app,
        *,
        requests_per_minute: int = 120,
        enabled: bool = True,
    ) -> None:
        super().__init__(app)
        self.enabled = enabled
        self.limit = max(1, requests_per_minute)
        self.window_seconds = 60

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.enabled:
            return await call_next(request)
        client = request.client
        ip = client.host if client else "unknown"
        now = time.time()
        window_start = now - self.window_seconds
        bucket = _rate_buckets[ip]
        bucket[:] = [ts for ts in bucket if ts > window_start]
        if len(bucket) >= self.limit:
            return Response("Too Many Requests", status_code=429)
        bucket.append(now)
        return await call_next(request)


_rate_buckets: dict[str, list[float]] = defaultdict(list)
