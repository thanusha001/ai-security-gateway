"""Structured JSON logging with secret redaction."""
from __future__ import annotations

import json
import logging
import sys
import time

from app.core.redaction import redact_secrets
from app.core.request_context import get_request_id, get_stage, get_user_id

_CONFIGURED = False


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "service": "ai-security-gateway",
            "event": record.getMessage(),
            "request_id": get_request_id(),
            "user_id": get_user_id(),
            "stage": get_stage(),
        }
        data = getattr(record, "extra_data", None)
        if isinstance(data, dict):
            payload.update(redact_secrets(data))
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def setup_logging() -> None:
    global _CONFIGURED
    if _CONFIGURED:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.DEBUG if settings_debug() else logging.INFO)
    logging.getLogger("uvicorn.access").handlers = [handler]
    logging.getLogger("uvicorn.error").handlers = [handler]
    _CONFIGURED = True


def settings_debug() -> bool:
    from app.core.config import settings

    return settings.debug


def get_logger(name: str) -> "KwargsLogger":
    return KwargsLogger(name)


class KwargsLogger:
    """Stdlib logger wrapper accepting keyword args as structured fields."""

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _log(self, level: int, event: str, exc_info=None, **kwargs) -> None:
        self._logger.log(
            level, event,
            extra={"extra_data": redact_secrets(kwargs)},
            exc_info=exc_info,
            stacklevel=3,
        )

    def debug(self, event: str, **kwargs) -> None:
        self._log(logging.DEBUG, event, **kwargs)

    def info(self, event: str, **kwargs) -> None:
        self._log(logging.INFO, event, **kwargs)

    def warning(self, event: str, **kwargs) -> None:
        self._log(logging.WARNING, event, **kwargs)

    def error(self, event: str, **kwargs) -> None:
        self._log(logging.ERROR, event, **kwargs)

    def exception(self, event: str, **kwargs) -> None:
        self._log(logging.ERROR, event, exc_info=True, **kwargs)
