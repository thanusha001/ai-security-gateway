"""Context security (spec §16).

Runs AFTER retrieval, BEFORE the LLM call. Each retrieved chunk gets an
include/exclude decision with a recorded reason. Fail-closed: if a chunk's
status cannot be determined, it is excluded (configurable via policy
fail_closed_on_context_uncertainty, default true).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from app.rag.vector_search import RetrievedChunk
from app.security.detectors import PromptInjectionDetector, SecretDetector
from app.security.detectors.rag_poisoning import RagPoisoningDetector
from app.security.pipeline import InputSecurityResult


@dataclass
class ChunkSecurityDecision:
    chunk_id: int
    included: bool
    security_status: str
    risk_score: float
    exclusion_reason: str | None = None
    detection: InputSecurityResult | None = None


@dataclass
class ContextSecurityResult:
    decisions: list[ChunkSecurityDecision] = field(default_factory=list)
    scan_latency_ms: float = 0.0
    included_chunks: list[RetrievedChunk] = field(default_factory=list)
    excluded_count: int = 0

    def context_text(self) -> str:
        return "\n\n".join(c.text for c in self.included_chunks)


def run_context_security(
    chunks: list[RetrievedChunk],
    *,
    allow_suspicious: bool = False,
    fail_closed: bool = True,
) -> ContextSecurityResult:
    """Scan each retrieved chunk; decide inclusion with recorded reasons."""
    start = time.perf_counter()
    injector = PromptInjectionDetector()
    poisoner = RagPoisoningDetector()
    secret_scanner = SecretDetector()

    result = ContextSecurityResult()
    for chunk in chunks:
        detection_results = [
            injector.analyze_timed(chunk.text, {"source": "retrieved_context"}),
            poisoner.analyze_timed(chunk.text, {"source": "retrieved_context"}),
            secret_scanner.analyze_timed(chunk.text, {"source": "retrieved_context"}),
        ]
        scan = InputSecurityResult(detection_results)
        max_risk = scan.max_risk

        # status from DB chunk metadata combined with fresh scan
        status = chunk.security_status
        if max_risk >= 0.60:
            status = "BLOCKED"
        elif max_risk >= 0.30:
            status = "SUSPICIOUS"
        elif status in ("BLOCKED", "SUSPICIOUS"):
            # DB status persists; fresh scan is clean but stored status stands
            pass

        included = True
        reason = None
        if status == "BLOCKED":
            included, reason = False, "chunk blocked by security scan"
        elif status == "SUSPICIOUS" and not allow_suspicious:
            included, reason = False, "suspicious chunk excluded by default policy"
        elif status == "UNKNOWN" and fail_closed:
            included, reason = False, "unknown security status; fail-closed"

        result.decisions.append(ChunkSecurityDecision(
            chunk_id=chunk.chunk_id,
            included=included,
            security_status=status,
            risk_score=max_risk,
            exclusion_reason=reason,
            detection=scan,
        ))
        if included:
            result.included_chunks.append(chunk)
        else:
            result.excluded_count += 1

    result.scan_latency_ms = round((time.perf_counter() - start) * 1000, 2)
    return result
