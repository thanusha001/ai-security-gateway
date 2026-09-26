"""Security detector framework.

Every detector implements the SecurityDetector interface and returns a
DetectionResult. This makes detectors replaceable, testable, and individually
evaluable (see scripts/evaluate_detectors.py and data/security_tests).
"""
from __future__ import annotations

import time
from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAction(StrEnum):
    ALLOW = "ALLOW"
    REDACT = "REDACT"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"


class ThreatType(StrEnum):
    NONE = "none"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    SYSTEM_PROMPT_EXTRACTION = "system_prompt_extraction"
    SECRET_DETECTION = "secret_detection"
    PII_DETECTION = "pii_detection"
    DOCUMENT_POISONING = "document_poisoning"
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    UNSAFE_CONTENT = "unsafe_content"


class DetectionResult(BaseModel):
    """Structured result of a single security detector run."""

    detector: str
    detector_version: str
    threat_type: ThreatType = ThreatType.NONE
    severity: Severity = Severity.NONE
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    action: SecurityAction = SecurityAction.ALLOW
    reason: str = ""
    evidence: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def detected(self) -> bool:
        return self.threat_type != ThreatType.NONE and self.risk_score > 0.0


class SecurityDetector(ABC):
    """Common interface for all security detectors."""

    #: unique detector name, e.g. "prompt_injection"
    name: str = "detector"
    #: semantic version, recorded with every security event for later evaluation
    version: str = "1.0.0"

    @abstractmethod
    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        """Analyze text and return a structured detection result."""

    def analyze_timed(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        start = time.perf_counter()
        result = self.analyze(text, context)
        result.latency_ms = round((time.perf_counter() - start) * 1000, 2)
        return result

    def health_check(self) -> bool:
        """Detectors are pure code by default; LLM-backed ones override this."""
        return True
