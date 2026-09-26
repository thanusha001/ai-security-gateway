"""Observability routes: security events, requests, metrics, SSE stream."""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import Role, decode_token, optional_user, require_roles
from app.database.models import (
    AuditLog,
    GatewayRequest,
    LLMRequest,
    RateLimitEvent,
    RetrievalEvent,
    SecurityEvent,
    ThreatDetection,
)
from app.database.models import User
from app.database.session import SessionLocal, get_db
from app.observability.events import bus

router = APIRouter(prefix="/api/v1", tags=["observability"])


@router.get("/requests")
async def list_requests(
    limit: int = Query(default=50, le=200),
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR, Role.USER)),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(GatewayRequest).order_by(GatewayRequest.created_at.desc()).limit(limit)
    if user.role == "USER":
        stmt = stmt.where(GatewayRequest.user_id == user.id)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "request_id": r.request_id, "user_id": r.user_id, "status": r.status,
            "risk_score": r.risk_score, "risk_level": r.risk_level,
            "final_decision": r.final_decision, "policy_version": r.policy_version,
            "total_latency_ms": r.total_latency_ms, "created_at": r.created_at.isoformat(),
            "input_preview": (r.input_text or "")[:120],
        }
        for r in rows
    ]


@router.get("/requests/{request_id}")
async def get_request_detail(
    request_id: str,
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR, Role.USER)),
    db: AsyncSession = Depends(get_db),
):
    row = (
        await db.execute(select(GatewayRequest).where(GatewayRequest.request_id == request_id))
    ).scalar_one_or_none()
    if row is None or (user.role == "USER" and row.user_id != user.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "NOT_FOUND", "message": "Unknown request ID"},
        )
    events = (
        await db.execute(
            select(SecurityEvent).where(SecurityEvent.request_id == request_id)
            .order_by(SecurityEvent.created_at)
        )
    ).scalars().all()
    retrievals = (
        await db.execute(
            select(RetrievalEvent).where(RetrievalEvent.request_id == request_id)
        )
    ).scalars().all()
    llm = (
        await db.execute(select(LLMRequest).where(LLMRequest.request_id == request_id))
    ).scalars().all()
    threats = (
        await db.execute(
            select(ThreatDetection).where(ThreatDetection.request_id == request_id)
        )
    ).scalars().all()

    return {
        "request": {
            "request_id": row.request_id, "user_id": row.user_id, "status": row.status,
            "risk_score": row.risk_score, "risk_level": row.risk_level,
            "final_decision": row.final_decision, "policy_id": row.policy_id,
            "policy_version": row.policy_version, "total_latency_ms": row.total_latency_ms,
            "error_code": row.error_code,
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "completed_at": row.completed_at.isoformat() if row.completed_at else None,
            "input_text": row.input_text,
            "response_text": row.response_text,
        },
        "events": [
            {
                "stage": e.stage, "event_type": e.event_type, "status": e.status,
                "severity": e.severity, "confidence": e.confidence,
                "risk_score": e.risk_score, "action": e.action, "detector": e.detector,
                "detector_version": e.detector_version, "reason": e.reason,
                "evidence": e.evidence_json, "latency_ms": e.latency_ms,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
        "retrievals": [
            {
                "document_id": r.document_id, "chunk_id": r.chunk_id,
                "similarity": r.similarity, "included": r.included,
                "exclusion_reason": r.exclusion_reason,
                "security_status": r.security_status,
            }
            for r in retrievals
        ],
        "llm": [
            {
                "provider": l.provider, "model": l.model,
                "input_tokens": l.input_tokens, "output_tokens": l.output_tokens,
                "total_tokens": l.total_tokens,
                "token_count_source": l.token_count_source,
                "generation_latency_ms": l.generation_latency_ms,
                "tokens_per_second": l.tokens_per_second,
                "status": l.status, "error_code": l.error_code,
            }
            for l in llm
        ],
        "threats": [
            {
                "threat_type": t.threat_type, "severity": t.severity,
                "confidence": t.confidence, "risk_score": t.risk_score,
                "detector": t.detector, "evidence": t.evidence_json,
            }
            for t in threats
        ],
    }


@router.get("/events")
async def list_events(
    limit: int = Query(default=100, le=500),
    severity: str | None = None,
    detector: str | None = None,
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit)
    if severity:
        stmt = stmt.where(SecurityEvent.severity == severity)
    if detector:
        stmt = stmt.where(SecurityEvent.detector == detector)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": e.id, "request_id": e.request_id, "stage": e.stage,
            "event_type": e.event_type, "status": e.status, "severity": e.severity,
            "confidence": e.confidence, "risk_score": e.risk_score, "action": e.action,
            "detector": e.detector, "detector_version": e.detector_version,
            "reason": e.reason, "evidence": e.evidence_json, "latency_ms": e.latency_ms,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in rows
    ]


@router.get("/threats")
async def list_threats(
    limit: int = Query(default=100, le=500),
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(ThreatDetection).order_by(ThreatDetection.created_at.desc()).limit(limit)
        )
    ).scalars().all()
    return [
        {
            "request_id": t.request_id, "threat_type": t.threat_type,
            "severity": t.severity, "confidence": t.confidence,
            "risk_score": t.risk_score, "detector": t.detector,
            "evidence": t.evidence_json,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        }
        for t in rows
    ]


@router.get("/metrics")
async def metrics(
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR, Role.USER)),
    db: AsyncSession = Depends(get_db),
):
    """Real aggregate metrics from the database (spec §51)."""

    async def scalar(stmt):
        return (await db.execute(stmt)).scalar() or 0

    total = await scalar(select(func.count(GatewayRequest.id)))
    allowed = await scalar(select(func.count(GatewayRequest.id))
                           .where(GatewayRequest.final_decision == "ALLOW"))
    blocked = await scalar(select(func.count(GatewayRequest.id))
                           .where(GatewayRequest.final_decision == "BLOCK"))
    redacted = await scalar(select(func.count(GatewayRequest.id))
                            .where(GatewayRequest.final_decision == "REDACT"))
    escalated = await scalar(select(func.count(GatewayRequest.id))
                             .where(GatewayRequest.final_decision == "ESCALATE"))
    threat_count = await scalar(select(func.count(ThreatDetection.id)))
    avg_risk = await scalar(select(func.avg(GatewayRequest.risk_score)))
    avg_latency = await scalar(select(func.avg(GatewayRequest.total_latency_ms)))
    llm_requests = await scalar(select(func.count(LLMRequest.id)))
    total_input_tokens = await scalar(select(func.sum(LLMRequest.input_tokens)))
    total_output_tokens = await scalar(select(func.sum(LLMRequest.output_tokens)))
    total_tokens = await scalar(select(func.sum(LLMRequest.total_tokens)))

    # P95 latency from real request rows (last 1000)
    latencies = (
        await db.execute(
            select(GatewayRequest.total_latency_ms)
            .where(GatewayRequest.total_latency_ms.is_not(None))
            .order_by(GatewayRequest.total_latency_ms.desc())
            .limit(1000)
        )
    ).scalars().all()
    p95 = latencies[int(len(latencies) * 0.05)] if latencies else None

    detector_counts_rows = (
        await db.execute(
            select(ThreatDetection.detector, func.count(ThreatDetection.id))
            .group_by(ThreatDetection.detector)
        )
    ).all()

    return {
        "total_requests": total,
        "allowed_requests": allowed,
        "blocked_requests": blocked,
        "redacted_requests": redacted,
        "escalated_requests": escalated,
        "threat_count": threat_count,
        "average_risk_score": round(float(avg_risk), 3) if avg_risk is not None else None,
        "average_latency_ms": round(float(avg_latency), 1) if avg_latency is not None else None,
        "p95_latency_ms": round(float(p95), 1) if p95 is not None else None,
        "llm_requests": llm_requests,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_tokens": total_tokens,
        "detector_counts": {row[0]: row[1] for row in detector_counts_rows},
    }


@router.get("/llm/usage")
async def llm_usage(
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    rows = (
        await db.execute(
            select(
                LLMRequest.model, LLMRequest.provider,
                func.count(LLMRequest.id),
                func.sum(LLMRequest.input_tokens), func.sum(LLMRequest.output_tokens),
                func.sum(LLMRequest.total_tokens),
                func.avg(LLMRequest.generation_latency_ms),
                func.avg(LLMRequest.tokens_per_second),
                func.count(LLMRequest.id).filter(LLMRequest.status == "failed"),
            )
            .group_by(LLMRequest.model, LLMRequest.provider)
        )
    ).all()
    sources = (
        await db.execute(select(LLMRequest.token_count_source,
                                func.count(LLMRequest.id))
                         .group_by(LLMRequest.token_count_source))
    ).all()
    return {
        "models": [
            {
                "model": r[0], "provider": r[1], "requests": r[2],
                "input_tokens": r[3] or 0, "output_tokens": r[4] or 0,
                "total_tokens": r[5] or 0,
                "avg_generation_ms": round(float(r[6]), 1) if r[6] is not None else None,
                "avg_tokens_per_second": round(float(r[7]), 1) if r[7] is not None else None,
                "failures": r[8],
            }
            for r in rows
        ],
        "token_count_sources": {str(r[0]): r[1] for r in sources},
    }


@router.get("/audit")
async def audit_logs(
    limit: int = Query(default=100, le=500),
    action: str | None = None,
    user_id: int | None = None,
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    stmt = select(AuditLog).order_by(AuditLog.created_at.desc()).limit(limit)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if user_id:
        stmt = stmt.where(AuditLog.user_id == user_id)
    rows = (await db.execute(stmt)).scalars().all()
    return [
        {
            "id": a.id, "user_id": a.user_id, "request_id": a.request_id,
            "action": a.action, "resource_type": a.resource_type,
            "resource_id": a.resource_id, "details": a.details_json,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in rows
    ]


async def _user_from_stream_token(token: str) -> User:
    """Resolve an EventSource ?token= query param the same way a bearer header
    would. EventSource cannot send Authorization headers, so this is the only
    way for the browser's native client to authenticate the stream."""
    try:
        payload = decode_token(token)
    except HTTPException:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_FAILED", "message": "Invalid stream token"},
        )
    user_id = int(payload.get("sub", 0))
    async with SessionLocal() as db:
        return await get_user_or_401(db, user_id)


@router.get("/stream")
async def event_stream(
    request: Request,
    token: str | None = None,
    user: User | None = Depends(optional_user),
):
    """SSE stream of live pipeline events.

    Auth accepts either a bearer header or `?token=<jwt>`. The query-param path
    exists because the browser's native EventSource cannot attach headers, and
    the live-requests console uses EventSource. Both paths enforce role access
    (ADMIN/AUDITOR/USER)."""
    if token:
        user = await _user_from_stream_token(token)
    if user is None or user.role not in {Role.ADMIN.value, Role.AUDITOR.value, Role.USER.value}:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_FAILED", "message": "Missing stream token"},
        )

    async def generator():
        queue = bus.subscribe()
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event, default=str)}\n\n"
        finally:
            bus.unsubscribe(queue)

    return StreamingResponse(
        generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )
