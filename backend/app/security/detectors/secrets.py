"""Secret detection + redaction detector (v1).

Detects credentials, API keys, JWTs, private keys, connection strings, and
password assignments. Supports redaction: matched spans are replaced with
labeled placeholders so downstream consumers never see raw secrets.
"""
from __future__ import annotations

import re
from typing import Any

from app.security.base import DetectionResult, SecurityAction, SecurityDetector, Severity, ThreatType
from app.security.patterns import (
    AWS_ACCESS_KEY_PATTERN,
    AWS_SECRET_KEY_PATTERN,
    BEARER_TOKEN_PATTERN,
    DATABASE_URL_PATTERN,
    GITHUB_TOKEN_PATTERN,
    GOOGLE_API_KEY_PATTERN,
    JWT_PATTERN,
    PRIVATE_KEY_PATTERN,
    SECRET_KEYWORD_ASSIGNMENT_PATTERN,
    SLACK_TOKEN_PATTERN,
    STRIPE_KEY_PATTERN,
)

# ordered most-specific first
_SECRET_RES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (PRIVATE_KEY_PATTERN, "private key", "[PRIVATE_KEY_REDACTED]"),
    (JWT_PATTERN, "JWT", "[JWT_REDACTED]"),
    (BEARER_TOKEN_PATTERN, "bearer token", "[BEARER_REDACTED]"),
    (AWS_ACCESS_KEY_PATTERN, "AWS access key", "[AWS_KEY_REDACTED]"),
    (GITHUB_TOKEN_PATTERN, "GitHub token", "[GITHUB_TOKEN_REDACTED]"),
    (GOOGLE_API_KEY_PATTERN, "Google API key", "[API_KEY_REDACTED]"),
    (STRIPE_KEY_PATTERN, "Stripe key", "[API_KEY_REDACTED]"),
    (SLACK_TOKEN_PATTERN, "Slack token", "[SLACK_TOKEN_REDACTED]"),
    (SECRET_KEYWORD_ASSIGNMENT_PATTERN, "credential assignment", "[SECRET_REDACTED]"),
    (DATABASE_URL_PATTERN, "connection string", "[CONNECTION_STRING_REDACTED]"),
)


class SecretDetector(SecurityDetector):
    name = "secret_detection"
    version = "1.1.0"

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        evidence: list[str] = []
        redactions: list[tuple[str, str]] = []

        for regex, label, placeholder in _SECRET_RES:
            for match in regex.finditer(text):
                # prefer the named 'value' group where the pattern defines one
                value = (match.group("value") if "value" in (match.re.groupindex or {})
                         else match.group(1) if match.groups() else match.group(0))
                evidence.append(f"{label}: {value[:12]}…")
                redactions.append((value, placeholder))

        if not evidence:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.9, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="No secrets detected",
            )

        # AWS secret keys are only flagged in the context of other secret signals
        # or explicit key assignment, to avoid flagging random 40-char strings.
        aws_secret_hits = AWS_SECRET_KEY_PATTERN.findall(text)
        if aws_secret_hits and len(evidence) >= 1 and "credential assignment" in " ".join(evidence):
            for value in aws_secret_hits[:2]:
                evidence.append(f"AWS secret key: {value[:12]}…")
                redactions.append((value, "[AWS_SECRET_REDACTED]"))

        redacted_text = text
        for value, placeholder in redactions:
            if value in redacted_text:
                redacted_text = redacted_text.replace(value, placeholder)

        score = min(1.0, 0.55 + 0.12 * (len(redactions) - 1))
        return DetectionResult(
            detector=self.name, detector_version=self.version,
            threat_type=ThreatType.SECRET_DETECTION,
            severity=Severity.CRITICAL if len(redactions) >= 3 else Severity.HIGH,
            confidence=0.95,
            risk_score=round(score, 3),
            action=SecurityAction.REDACT,
            reason=f"{len(redactions)} secret(s) detected",
            evidence=evidence[:10],
            metadata={"redacted_text": redacted_text, "redaction_count": len(redactions)},
        )
