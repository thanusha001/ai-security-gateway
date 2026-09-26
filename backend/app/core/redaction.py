"""Shared redaction helpers.

Sensitive values must never reach logs, audit records, or stored evidence in
raw form. These helpers scrub secrets (API keys, JWTs, bearer tokens,
connection strings, private keys) and optionally PII from arbitrary strings.

The canonical detection patterns live in app.security.patterns and are shared
with the security detectors so that redaction and detection never drift apart.
"""
from __future__ import annotations

import re
from typing import Any

from app.security.patterns import (
    AWS_ACCESS_KEY_PATTERN,
    BEARER_TOKEN_PATTERN,
    CREDIT_CARD_PATTERN,
    DATABASE_URL_PATTERN,
    EMAIL_PATTERN,
    IP_ADDRESS_PATTERN,
    JWT_PATTERN,
    PHONE_PATTERN_INTERNATIONAL,
    PRIVATE_KEY_PATTERN,
    SLACK_TOKEN_PATTERN,
    SECRET_KEYWORD_ASSIGNMENT_PATTERN,
)

# Ordered: most specific first so greedy patterns don't eat narrower matches.
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (PRIVATE_KEY_PATTERN, "[PRIVATE_KEY_REDACTED]"),
    (JWT_PATTERN, "[JWT_REDACTED]"),
    (BEARER_TOKEN_PATTERN, "[BEARER_REDACTED]"),
    (AWS_ACCESS_KEY_PATTERN, "[AWS_KEY_REDACTED]"),
    (SLACK_TOKEN_PATTERN, "[SLACK_TOKEN_REDACTED]"),
    (DATABASE_URL_PATTERN, "[CONNECTION_STRING_REDACTED]"),
    (SECRET_KEYWORD_ASSIGNMENT_PATTERN, "[SECRET_REDACTED]"),
)

_PII_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (EMAIL_PATTERN, "[EMAIL_REDACTED]"),
    (CREDIT_CARD_PATTERN, "[CREDIT_CARD_REDACTED]"),
    (PHONE_PATTERN_INTERNATIONAL, "[PHONE_REDACTED]"),
    (IP_ADDRESS_PATTERN, "[IP_REDACTED]"),
)

# Redaction of secrets is always on; PII redaction in logs is opt-in via env
# (the PII detector handles request-level redaction separately).
REDACT_PII_IN_LOGS = False


def redact_secrets(value: Any) -> Any:
    """Recursively redact secret-looking substrings from strings in any structure."""
    if isinstance(value, str):
        result = value
        for pattern, replacement in _SECRET_PATTERNS:
            result = pattern.sub(replacement, result)
        if REDACT_PII_IN_LOGS:
            for pattern, replacement in _PII_PATTERNS:
                result = pattern.sub(replacement, result)
        return result
    if isinstance(value, dict):
        return {k: redact_secrets(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(redact_secrets(v) for v in value)  # type: ignore[return-value]
    return value
