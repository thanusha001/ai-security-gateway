"""PII detection + redaction detector (v1).

Detects emails, phone numbers, IPs, credit-card-like numbers, and national
identifiers (SSN/IBAN). Names are intentionally NOT detected: without entity
context this produces too many false positives; documented as a limitation.
"""
from __future__ import annotations

import re
from typing import Any

from app.security.base import DetectionResult, SecurityAction, SecurityDetector, Severity, ThreatType
from app.security.patterns import (
    CREDIT_CARD_PATTERN,
    EMAIL_PATTERN,
    IBAN_PATTERN,
    IP_ADDRESS_PATTERN,
    PHONE_PATTERN_INTERNATIONAL,
    SSN_PATTERN,
)


def _luhn_valid(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 16:
        return False
    checksum = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


class PIIDetector(SecurityDetector):
    name = "pii_detection"
    version = "1.0.0"

    # credit card BEFORE phone: 16-digit groups would otherwise read as phone
    _RES: tuple[tuple[re.Pattern[str], str, str], ...] = (
        (EMAIL_PATTERN, "email", "[EMAIL_REDACTED]"),
        (SSN_PATTERN, "national id", "[NATIONAL_ID_REDACTED]"),
        (IBAN_PATTERN, "IBAN", "[IBAN_REDACTED]"),
        (IP_ADDRESS_PATTERN, "IP address", "[IP_REDACTED]"),
        (CREDIT_CARD_PATTERN, "credit card", "[CREDIT_CARD_REDACTED]"),
        (PHONE_PATTERN_INTERNATIONAL, "phone", "[PHONE_REDACTED]"),
    )

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        evidence: list[str] = []
        redactions: list[tuple[str, str]] = []

        for regex, label, placeholder in self._RES:
            for match in regex.finditer(text):
                value = match.group(0)
                # credit-card-like only if the Luhn checksum passes
                if label == "credit card" and not _luhn_valid(value):
                    continue
                # avoid IP-vs-phone double reporting: skip if it matches IP shape
                if label == "phone" and IP_ADDRESS_PATTERN.fullmatch(value):
                    continue
                evidence.append(f"{label}: {value[:14]}")
                redactions.append((value, placeholder))

        if not evidence:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.9, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="No PII detected",
            )

        redacted_text = text
        for value, placeholder in redactions:
            if value in redacted_text:
                redacted_text = redacted_text.replace(value, placeholder)

        score = min(0.9, 0.4 + 0.1 * len(redactions))
        return DetectionResult(
            detector=self.name, detector_version=self.version,
            threat_type=ThreatType.PII_DETECTION,
            severity=Severity.MEDIUM if len(redactions) <= 2 else Severity.HIGH,
            confidence=0.9,
            risk_score=round(score, 3),
            action=SecurityAction.REDACT,
            reason=f"{len(redactions)} PII item(s) detected",
            evidence=evidence[:10],
            metadata={"redacted_text": redacted_text, "redaction_count": len(redactions)},
        )
