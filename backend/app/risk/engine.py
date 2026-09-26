"""Risk engine.

Aggregates detector signals into a single risk score. Aggregation logic is
documented and configurable; it is NOT a naive average:

    risk = max(individual scores)
            then weighted average with the max to prevent score dilution when
            many low-signal detectors run on benign input.

    risk = 0.5 * max_score + 0.5 * weighted_avg

Rationale: a single strong signal (e.g. confirmed prompt injection 0.9) must
not be diluted by eight detectors returning 0.0; a weighted average alone
would. The weighted component lets several medium signals accumulate.

Thresholds are initial policy values and REQUIRE EMPIRICAL EVALUATION — see
scripts/evaluate_detectors.py and docs/security-model.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from app.security.base import DetectionResult


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskConfig:
    """Configurable aggregation parameters (overridable per policy)."""

    weights: dict[str, float] = field(default_factory=lambda: {
        "prompt_injection": 1.0,
        "jailbreak": 1.0,
        "secret_detection": 0.9,
        "pii_detection": 0.6,
        "document_poisoning": 1.0,
        "system_prompt_leakage": 0.9,
        "unsafe_content": 0.8,
    })
    max_weight: float = 0.6
    avg_weight: float = 0.4
    threshold_medium: float = 0.30
    threshold_high: float = 0.60
    threshold_critical: float = 0.80


def classify_level(score: float, config: RiskConfig | None = None) -> RiskLevel:
    config = config or RiskConfig()
    if score >= config.threshold_critical:
        return RiskLevel.CRITICAL
    if score >= config.threshold_high:
        return RiskLevel.HIGH
    if score >= config.threshold_medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def calculate_risk(results: list[DetectionResult], config: RiskConfig | None = None) -> tuple[float, RiskLevel]:
    """Aggregate detector results into (risk_score, risk_level)."""
    config = config or RiskConfig()
    if not results:
        return 0.0, RiskLevel.LOW

    weighted = []
    total_weight = 0.0
    for r in results:
        w = config.weights.get(r.detector, 0.5)
        weighted.append(r.risk_score * w)
        total_weight += w

    max_score = max(r.risk_score for r in results)
    avg_score = (sum(weighted) / total_weight) if total_weight else 0.0
    score = config.max_weight * max_score + config.avg_weight * avg_score
    score = round(min(score, 1.0), 3)
    return score, classify_level(score, config)


def risk_breakdown(results: list[DetectionResult]) -> list[dict]:
    """Per-detector risk contribution, for UI display and explainability."""
    return [
        {
            "detector": r.detector,
            "risk_score": r.risk_score,
            "severity": r.severity.value,
            "confidence": r.confidence,
            "action": r.action.value,
            "latency_ms": r.latency_ms,
            "reason": r.reason,
        }
        for r in results
    ]