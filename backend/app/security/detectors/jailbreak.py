"""Jailbreak detector (v1.1).

Detects attempts to bypass model safety restrictions: persona attacks
("do anything now"), filter-bypass language, and "no rules" framings.

v1.1: legitimate *defensive/technical* mentions ("developer mode in the IDE",
"the pen test will bypass the filter") are suppressed via question-context
analysis; evaluation showed v1.0 had a 0.667 FPR from exactly these cases.
"""
from __future__ import annotations

from typing import Any

from app.security.base import DetectionResult, SecurityAction, SecurityDetector, Severity, ThreatType
from app.security.patterns import JAILBREAK_PHRASES, phrase_matcher

_JAILBREAK_RE = phrase_matcher(JAILBREAK_PHRASES)

# Legitimate contexts where jailbreak-sounding phrases appear innocently.
# Detection fires only when the phrase is NOT accompanied by these markers.
_DEFENSIVE_CONTEXT_MARKERS = (
    "how do i", "how to", "what is", "explain", "documentation", "in the ide",
    "visual studio", "enable developer mode in", "pen test", "pentest",
    "security team", "will bypass", "training", "chapter", "handbook",
    "our email gateway", "in visual studio",
)

# Second-person directives aimed AT the model (stronger signal than phrase alone)
_SECOND_PERSON_DIRECTIVE = (
    "you are now", "you must", "you can do anything", "you have no",
    "ignore your", "bypass your", "act as", "from now on you",
)


class JailbreakDetector(SecurityDetector):
    name = "jailbreak"
    version = "1.1.0"

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        lowered = text.lower()
        hits = sorted(set(_JAILBREAK_RE.findall(lowered)), key=len, reverse=True)
        if not hits:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.9, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="No jailbreak signals",
            )

        # Context suppression: phrase present but framed as a question about
        # tooling, or as a defensive action by humans — not an attack attempt.
        has_directive = any(d in lowered for d in _SECOND_PERSON_DIRECTIVE)
        defensive = any(m in lowered for m in _DEFENSIVE_CONTEXT_MARKERS)
        if defensive and not has_directive:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.NONE, severity=Severity.NONE,
                confidence=0.6, risk_score=0.0, action=SecurityAction.ALLOW,
                reason="Jailbreak phrase in legitimate technical/defensive context",
                evidence=[f"suppressed: {hits[0]}"],
            )

        score = min(1.0, 0.55 + 0.15 * (len(hits) - 1))
        if not has_directive and len(hits) == 1:
            score = min(score, 0.45)  # lone phrase without directive: suspicious, not certain
        return DetectionResult(
            detector=self.name, detector_version=self.version,
            threat_type=ThreatType.JAILBREAK,
            severity=Severity.HIGH if score >= 0.7 else Severity.MEDIUM,
            confidence=min(0.92, 0.6 + 0.1 * len(hits)),
            risk_score=round(score, 3),
            action=SecurityAction.BLOCK if score >= 0.5 else SecurityAction.SANITIZE,
            reason="Attempt to bypass model safety restrictions",
            evidence=[f"jailbreak phrase: {h}" for h in hits[:5]],
        )
