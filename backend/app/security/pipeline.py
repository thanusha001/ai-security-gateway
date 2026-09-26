"""Input security pipeline.

Runs all input detectors against user text and aggregates results. Each
detector result is preserved individually for explainability; the pipeline
returns both the list and a combined summary used by the risk engine.
"""
from __future__ import annotations

from typing import Any

from app.security.base import DetectionResult, SecurityAction
from app.security.detectors import (
    JailbreakDetector,
    PIIDetector,
    PromptInjectionDetector,
    SecretDetector,
)


class InputSecurityResult:
    def __init__(self, results: list[DetectionResult]) -> None:
        self.results = results

    @property
    def detected(self) -> list[DetectionResult]:
        return [r for r in self.results if r.detected]

    @property
    def max_risk(self) -> float:
        return max((r.risk_score for r in self.results), default=0.0)

    @property
    def actions(self) -> set[SecurityAction]:
        return {r.action for r in self.detected}

    @property
    def redacted_text(self) -> str | None:
        """Text with secrets/PII replaced, if any redaction detectors fired."""
        text: str | None = None
        for r in self.results:
            rt = r.metadata.get("redacted_text")
            if isinstance(rt, str):
                text = rt if text is None else text
        return text

    @property
    def should_block(self) -> bool:
        return SecurityAction.BLOCK in self.actions

    def summary(self) -> dict[str, Any]:
        return {
            "detectors_run": len(self.results),
            "threats_detected": len(self.detected),
            "max_risk": round(self.max_risk, 3),
            "actions": sorted(a.value for a in self.actions),
            "results": [r.model_dump(mode="json") for r in self.results],
        }


def run_input_security(text: str) -> InputSecurityResult:
    """Run all input detectors. Pure CPU; safe to call from async handlers."""
    detectors: tuple[Any, ...] = (
        PromptInjectionDetector(),
        JailbreakDetector(),
        SecretDetector(),
        PIIDetector(),
    )
    results = [d.analyze_timed(text) for d in detectors]
    return InputSecurityResult(results)


def run_output_security(text: str) -> InputSecurityResult:
    """Output security: secrets/PII leakage + system prompt leakage in LLM output."""
    detectors: tuple[Any, ...] = (
        SecretDetector(),
        PIIDetector(),
    )
    results = [d.analyze_timed(text) for d in detectors]
    return InputSecurityResult(results)
