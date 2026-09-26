"""RAG document poisoning detector (v1).

Detects instructions embedded in documents that try to manipulate the LLM:
extraction requests, privilege escalation, hidden instructions, and exfil.
Explicitly suppresses false positives from legitimate policy language
("employees must comply…", company policy text, password policy text).
"""
from __future__ import annotations

from typing import Any

from app.security.base import DetectionResult, SecurityAction, SecurityDetector, Severity, ThreatType
from app.security.patterns import LEGITIMATE_POLICY_MARKERS, POISONING_PHRASES, phrase_matcher

_POISONING_RE = phrase_matcher(POISONING_PHRASES)


class RagPoisoningDetector(SecurityDetector):
    name = "rag_poisoning"
    version = "1.0.0"

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        lowered = text.lower()
        hits = sorted(set(_POISONING_RE.findall(lowered)), key=len, reverse=True)
        if not hits:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.9, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="No poisoning signals",
            )

        # Policy documents legitimately contain imperatives and even the word
        # "secretly" in prose. Require a directive + action pattern: the hit
        # must look like an instruction to the *model*, not a rule for humans.
        policy_context = any(m in lowered for m in LEGITIMATE_POLICY_MARKERS)
        if policy_context and len(hits) == 1:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.6, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="Single weak signal in policy-style text",
                evidence=[f"suppressed: {hits[0]}"],
            )

        score = min(1.0, 0.5 + 0.12 * (len(hits) - 1))
        return DetectionResult(
            detector=self.name, detector_version=self.version,
            threat_type=ThreatType.DOCUMENT_POISONING,
            severity=Severity.HIGH if score >= 0.6 else Severity.MEDIUM,
            confidence=min(0.9, 0.55 + 0.1 * len(hits)),
            risk_score=round(score, 3),
            action=SecurityAction.BLOCK if score >= 0.6 else SecurityAction.SANITIZE,
            reason="Document embeds instructions targeting the AI assistant",
            evidence=[f"poisoning phrase: {h}" for h in hits[:5]],
        )
