"""Observability events.

Every pipeline stage emits structured events. Events are persisted in
security_events (via the pipeline service) and broadcast to an in-process bus
consumed by the SSE endpoint for the live pipeline UI.
"""
from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any


class Stage(StrEnum):
    REQUEST_RECEIVED = "REQUEST_RECEIVED"
    REQUEST_VALIDATED = "REQUEST_VALIDATED"
    AUTHENTICATED = "AUTHENTICATED"
    INPUT_SECURITY_STARTED = "INPUT_SECURITY_STARTED"
    INPUT_SECURITY_COMPLETED = "INPUT_SECURITY_COMPLETED"
    RISK_CALCULATED = "RISK_CALCULATED"
    POLICY_EVALUATED = "POLICY_EVALUATED"
    RETRIEVAL_STARTED = "RETRIEVAL_STARTED"
    RETRIEVAL_COMPLETED = "RETRIEVAL_COMPLETED"
    CONTEXT_SECURITY_STARTED = "CONTEXT_SECURITY_STARTED"
    CONTEXT_SECURITY_COMPLETED = "CONTEXT_SECURITY_COMPLETED"
    LLM_STARTED = "LLM_STARTED"
    LLM_COMPLETED = "LLM_COMPLETED"
    OUTPUT_SECURITY_STARTED = "OUTPUT_SECURITY_STARTED"
    OUTPUT_SECURITY_COMPLETED = "OUTPUT_SECURITY_COMPLETED"
    FINAL_DECISION = "FINAL_DECISION"
    RESPONSE_SENT = "RESPONSE_SENT"
    STAGE_FAILED = "STAGE_FAILED"


class EventBus:
    """In-process pub/sub for live pipeline events (SSE consumers)."""

    def __init__(self, history_size: int = 500) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)
        self._history: deque[dict[str, Any]] = deque(maxlen=history_size)

    def publish(self, event: dict[str, Any]) -> None:
        event = dict(event)
        event.setdefault("ts", datetime.now(timezone.utc).isoformat())
        self._history.append(event)
        for queue in list(self._subscribers.get("*", set())):
            try:
                queue.put_nowait(event)
            except RuntimeError:
                pass

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers["*"].add(queue)
        for item in list(self._history):
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                break
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._subscribers["*"].discard(queue)


bus = EventBus()


def make_event(
    request_id: str,
    stage: str,
    status: str = "completed",
    duration_ms: float | None = None,
    **fields: Any,
) -> dict[str, Any]:
    event = {
        "request_id": request_id,
        "stage": stage,
        "status": status,
    }
    if duration_ms is not None:
        event["duration_ms"] = round(duration_ms, 2)
    event.update({k: v for k, v in fields.items() if v is not None})
    return event
