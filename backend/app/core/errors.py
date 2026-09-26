"""Centralized error handling.

Every API error is returned in one envelope:
    {"error": {"code", "message", "request_id", "details"}}
Stack traces never reach clients in production; they are logged internally.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from fastapi import Request
from fastapi.responses import JSONResponse

from app.core.config import settings
from app.core.request_context import get_request_id
from app.core.logging import get_logger

log = get_logger("errors")


class ErrorCode(StrEnum):
    VALIDATION_ERROR = "VALIDATION_ERROR"
    AUTHENTICATION_FAILED = "AUTHENTICATION_FAILED"
    AUTHORIZATION_FAILED = "AUTHORIZATION_FAILED"
    RATE_LIMITED = "RATE_LIMITED"
    DOCUMENT_TOO_LARGE = "DOCUMENT_TOO_LARGE"
    UNSUPPORTED_FILE = "UNSUPPORTED_FILE"
    INVALID_FILE = "INVALID_FILE"
    DUPLICATE_DOCUMENT = "DUPLICATE_DOCUMENT"
    DOCUMENT_PROCESSING_FAILED = "DOCUMENT_PROCESSING_FAILED"
    EMBEDDING_FAILED = "EMBEDDING_FAILED"
    VECTOR_DB_UNAVAILABLE = "VECTOR_DB_UNAVAILABLE"
    LLM_UNAVAILABLE = "LLM_UNAVAILABLE"
    LLM_TIMEOUT = "LLM_TIMEOUT"
    LLM_ERROR = "LLM_ERROR"
    SECURITY_BLOCKED = "SECURITY_BLOCKED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    OUTPUT_BLOCKED = "OUTPUT_BLOCKED"
    NOT_FOUND = "NOT_FOUND"
    INTERNAL_ERROR = "INTERNAL_ERROR"


class GatewayError(Exception):
    """Base exception carrying a machine-readable code and user-safe message."""

    def __init__(
        self,
        code: ErrorCode,
        message: str,
        status_code: int = 400,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or {}

    def to_response(self, request_id: str | None) -> JSONResponse:
        body = {
            "error": {
                "code": self.code.value,
                "message": self.message,
                "request_id": request_id,
                "details": self.details,
            }
        }
        return JSONResponse(status_code=self.status_code, content=body)


class LLMUnavailableError(GatewayError):
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            ErrorCode.LLM_UNAVAILABLE,
            "The configured LLM provider is unavailable",
            status_code=503,
            details=details,
        )


class LLMTimeoutError(GatewayError):
    def __init__(self, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            ErrorCode.LLM_TIMEOUT,
            "The LLM did not respond in time",
            status_code=504,
            details=details,
        )


class SecurityBlockedError(GatewayError):
    def __init__(self, message: str, details: dict[str, Any] | None = None) -> None:
        super().__init__(
            ErrorCode.SECURITY_BLOCKED,
            message,
            status_code=403,
            details=details,
        )


def _details_for_exception(exc: Exception) -> dict[str, Any]:
    if settings.is_production:
        return {"type": type(exc).__name__}
    return {"type": type(exc).__name__, "message": str(exc)[:500]}


async def gateway_error_handler(_: Request, exc: GatewayError) -> JSONResponse:
    log.error("gateway_error", error_code=exc.code.value, message=exc.message, details=exc.details)
    return exc.to_response(get_request_id())


async def unhandled_error_handler(_: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled_error", error_code=ErrorCode.INTERNAL_ERROR.value)
    return GatewayError(
        ErrorCode.INTERNAL_ERROR,
        "An unexpected error occurred",
        status_code=500,
        details=_details_for_exception(exc),
    ).to_response(get_request_id())
