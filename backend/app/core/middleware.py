"""HTTP middleware: request IDs, secure headers, size limits."""
from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.core.config import settings
from app.core.request_context import new_request_id, request_id_var


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request_id to every incoming request and records latency."""

    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("X-Request-ID") or new_request_id()
        # only accept client-supplied IDs matching safe charset
        if not request_id.isalnum() or len(request_id) > 64:
            request_id = new_request_id()
        token = request_id_var.set(request_id)
        request.state.request_id = request_id
        start = time.perf_counter()
        try:
            response = await call_next(request)
        finally:
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Response-Time-ms"] = f"{(time.perf_counter() - start) * 1000:.1f}"
        return response


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """Security headers on every response."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject bodies larger than MAX_UPLOAD_SIZE_MB + slack (413)."""

    def __init__(self, app, max_body_mb: int = 25) -> None:
        super().__init__(app)
        self.max_body_bytes = max_body_mb * 1024 * 1024

    async def dispatch(self, request: Request, call_next) -> Response:
        length = request.headers.get("content-length")
        if length and int(length) > self.max_body_bytes:
            return JSONResponse(
                status_code=413,
                content={"error": {
                    "code": "DOCUMENT_TOO_LARGE",
                    "message": f"Request body exceeds {self.max_body_bytes // (1024*1024)} MB",
                    "request_id": getattr(request.state, "request_id", None),
                    "details": {},
                }},
            )
        return await call_next(request)
