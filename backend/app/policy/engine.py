"""Policy engine.

Policies are stored in PostgreSQL (table security_policies) with versioning.
The engine evaluates detector results against the active policy's per-threat
rules and returns the final action. An invalid policy can never become active
(see services/policy_service.py validation).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.security.base import DetectionResult, SecurityAction, Severity, ThreatType


class PolicyRule(BaseModel):
    """Per-threat-type rule: threshold + action."""

    threshold: float = Field(ge=0.0, le=1.0)
    action: SecurityAction
    min_severity: Severity | None = None


class PolicyConfiguration(BaseModel):
    """Validated policy document stored in security_policies.configuration_json."""

    rules: dict[str, PolicyRule]
    risk_thresholds: dict[str, float] | None = None
    allow_suspicious_chunks: bool = False
    fail_closed_on_context_uncertainty: bool = True
    description: str | None = None

    model_config = {"extra": "forbid"}


DEFAULT_POLICY_CONFIG: dict[str, Any] = {
    "rules": {
        "prompt_injection": {"threshold": 0.60, "action": "BLOCK"},
        "jailbreak": {"threshold": 0.50, "action": "BLOCK"},
        "secret_detection": {"threshold": 0.30, "action": "REDACT"},
        "pii_detection": {"threshold": 0.30, "action": "REDACT"},
        "document_poisoning": {"threshold": 0.60, "action": "BLOCK"},
        "system_prompt_leakage": {"threshold": 0.60, "action": "REDACT"},
        "unsafe_content": {"threshold": 0.70, "action": "BLOCK"},
    },
    "risk_thresholds": {"medium": 0.30, "high": 0.60, "critical": 0.80},
    "allow_suspicious_chunks": False,
    "fail_closed_on_context_uncertainty": True,
}


class PolicyDecision(BaseModel):
    """Final action decided by the policy engine, with per-rule trace."""

    final_action: SecurityAction
    reason: str
    rule_traces: list[dict[str, Any]] = Field(default_factory=list)
    policy_id: int | None = None
    policy_version: int | None = None
    policy_name: str | None = None


class PolicyEngine:
    """Evaluates detection results against a policy configuration."""

    def evaluate(
        self,
        results: list[DetectionResult],
        config: PolicyConfiguration,
        policy_id: int | None = None,
        policy_version: int | None = None,
        policy_name: str | None = None,
    ) -> PolicyDecision:
        # action priority: BLOCK > ESCALATE > REDACT/SANITIZE > ALLOW
        priority = {
            SecurityAction.BLOCK: 4,
            SecurityAction.ESCALATE: 3,
            SecurityAction.REDACT: 2,
            SecurityAction.SANITIZE: 2,
            SecurityAction.ALLOW: 1,
        }
        traces: list[dict[str, Any]] = []
        final = SecurityAction.ALLOW
        reasons: list[str] = []

        for r in results:
            rule = config.rules.get(r.threat_type.value)
            if rule is None:
                continue
            if r.risk_score >= rule.threshold:
                if final is SecurityAction.ALLOW or priority[rule.action] > priority[final]:
                    final = rule.action
                    reasons.append(f"{r.threat_type.value} {r.risk_score:.2f} >= {rule.threshold:.2f} -> {rule.action.value}")
                traces.append({
                    "threat_type": r.threat_type.value,
                    "detector": r.detector,
                    "risk_score": r.risk_score,
                    "threshold": rule.threshold,
                    "action": rule.action.value,
                    "triggered": True,
                })
            else:
                traces.append({
                    "threat_type": r.threat_type.value,
                    "detector": r.detector,
                    "risk_score": r.risk_score,
                    "threshold": rule.threshold,
                    "action": rule.action.value,
                    "triggered": False,
                })

        reason = "; ".join(reasons) if reasons else "No policy rules triggered; allowed"
        return PolicyDecision(
            final_action=final,
            reason=reason,
            rule_traces=traces,
            policy_id=policy_id,
            policy_version=policy_version,
            policy_name=policy_name,
        )
