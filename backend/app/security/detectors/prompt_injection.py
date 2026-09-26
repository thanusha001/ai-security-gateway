"""Prompt injection detector (v1).

Combines multiple signals rather than naive keyword matching:
  1. Directive phrases (ignore/override/forget instructions)
  2. System-prompt extraction attempts
  3. Role/template manipulation markers (fake system tags)
  4. Imperative + meta-instruction heuristics

Limitations (documented, evaluated in scripts/evaluate_detectors.py):
deterministic rules miss novel paraphrases; an optional LLM classifier can be
enabled via LLM_SECURITY_CLASSIFIER_ENABLED for semantic double-checking.
"""
from __future__ import annotations

from typing import Any

from app.security.base import DetectionResult, SecurityAction, SecurityDetector, Severity, ThreatType
from app.security.patterns import (
    EXTRACTION_PHRASES,
    INJECTION_DIRECTIVES,
    LEGITIMATE_POLICY_MARKERS,
    phrase_matcher,
)

_DIRECTIVE_RE = phrase_matcher(INJECTION_DIRECTIVES)
_EXTRACTION_RE = phrase_matcher(EXTRACTION_PHRASES)
_ROLE_MARKERS_RE = phrase_matcher((
    "<|im_start|>system", "<|system|>", "### system:", "###system:",
    "[system]", "[/system]", "<<sys>>", "<|im_start|>", "[inst]",
    "system:", "assistant:", "user:",  # bare role words are weak signals
))


class PromptInjectionDetector(SecurityDetector):
    name = "prompt_injection"
    version = "1.1.0"

    # weights for signal aggregation (sum before normalization)
    W_DIRECTIVE = 0.45
    W_EXTRACTION = 0.35
    W_ROLE_MARKER = 0.20

    def analyze(self, text: str, context: dict[str, Any] | None = None) -> DetectionResult:
        evidence: list[str] = []
        score = 0.0
        lowered = text.lower()

        directives = _DIRECTIVE_RE.findall(lowered)
        if directives:
            score += self.W_DIRECTIVE
            evidence.append(f"directive phrase: {directives[0]}")

        extractions = _EXTRACTION_RE.findall(lowered)
        if extractions:
            score += self.W_EXTRACTION
            evidence.append(f"extraction attempt: {extractions[0]}")

        role_markers = [m for m in _ROLE_MARKERS_RE.findall(lowered)
                        if m.strip() not in ("system:", "assistant:", "user:")]
        strong_roles = [m for m in role_markers if "<" in m or "#" in m or "[" in m]
        if strong_roles:
            score += self.W_ROLE_MARKER
            evidence.append(f"role/template marker: {strong_roles[0]}")

        # multiple distinct directive phrases indicate a stronger attack
        if len(set(directives)) >= 2:
            score += 0.10
            evidence.append(f"multiple directives ({len(set(directives))} distinct)")

        # Suppress false positives: legitimate policy documents talk about
        # ignoring/overriding *documents* in a policy context, not LLM instructions.
        if score > 0 and any(m in lowered for m in LEGITIMATE_POLICY_MARKERS):
            hit = _DIRECTIVE_RE.search(lowered)
            if hit and not extractions and not strong_roles:
                score *= 0.5
                evidence.append("policy context detected; score reduced")

        score = min(score, 1.0)

        if score >= 0.60:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=Severity.HIGH, confidence=min(0.95, 0.5 + score / 2),
                risk_score=round(score, 3), action=SecurityAction.BLOCK,
                reason="Instruction attempts to override system behavior",
                evidence=evidence,
            )
        if score >= 0.30:
            return DetectionResult(
                detector=self.name, detector_version=self.version,
                threat_type=ThreatType.PROMPT_INJECTION,
                severity=Severity.MEDIUM, confidence=min(0.8, 0.4 + score / 2),
                risk_score=round(score, 3), action=SecurityAction.SANITIZE,
                reason="Possible instruction manipulation",
                evidence=evidence,
            )
        return DetectionResult(
            detector=self.name, detector_version=self.version,
            threat_type=ThreatType.NONE, severity=Severity.NONE,
            confidence=0.9, risk_score=0.0, action=SecurityAction.ALLOW,
            reason="No injection signals", evidence=evidence,
        )
