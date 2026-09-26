#!/usr/bin/env python3
"""Retention cleanup (spec §48).

Deletes audit_logs older than AUDIT_RETENTION_DAYS and security_events /
threat_detections older than SECURITY_EVENT_RETENTION_DAYS. Run via cron,
Task Scheduler, or manually:

    python scripts/maintenance.py          # from repo root

Also supports purging stored raw prompts/outputs when storage is disabled:
pass --purge-prompts to blank stored input/response text of existing rows
(one-time privacy action after flipping STORE_RAW_PROMPTS to false).
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from sqlalchemy import delete, update  # noqa: E402

from app.core.config import settings  # noqa: E402
from app.core.logging import setup_logging  # noqa: E402
from app.database.models import (  # noqa: E402
    AuditLog,
    GatewayRequest,
    SecurityEvent,
    ThreatDetection,
)
from app.database.session import SessionLocal, engine  # noqa: E402


async def cleanup(dry_run: bool = False, purge_prompts: bool = False) -> None:
    now = datetime.now(timezone.utc)
    audit_cutoff = now - timedelta(days=settings.audit_retention_days)
    event_cutoff = now - timedelta(days=settings.security_event_retention_days)

    async with SessionLocal() as db:
        audit_count = (await db.execute(
            select_count(AuditLog, audit_cutoff)
        )).scalar()
        event_count = (await db.execute(
            select_count(SecurityEvent, event_cutoff)
        )).scalar()
        threat_count = (await db.execute(
            select_count(ThreatDetection, event_cutoff)
        )).scalar()

        mode = "WOULD DELETE" if dry_run else "Deleted"
        print(f"{mode}: {audit_count} audit_logs older than {settings.audit_retention_days}d")
        print(f"{mode}: {event_count} security_events older than {settings.security_event_retention_days}d")
        print(f"{mode}: {threat_count} threat_detections older than {settings.security_event_retention_days}d")

        if not dry_run:
            await db.execute(delete(AuditLog).where(AuditLog.created_at < audit_cutoff))
            await db.execute(delete(SecurityEvent).where(SecurityEvent.created_at < event_cutoff))
            await db.execute(delete(ThreatDetection).where(ThreatDetection.created_at < event_cutoff))

        if purge_prompts:
            res = await db.execute(
                update(GatewayRequest)
                .where(GatewayRequest.input_text.is_not(None))
                .values(input_text="[PURGED:retention policy]")
            )
            print(f"{'WOULD PURGE' if dry_run else 'Purged'}: {res.rowcount} stored input texts")
            res = await db.execute(
                update(GatewayRequest)
                .where(GatewayRequest.response_text.is_not(None))
                .values(response_text="[PURGED:retention policy]")
            )
            print(f"{'WOULD PURGE' if dry_run else 'Purged'}: {res.rowcount} stored response texts")

        await db.commit()


def select_count(model, cutoff):
    from sqlalchemy import func, select

    return select(func.count(model.id)).where(model.created_at < cutoff)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AI Security Gateway retention cleanup")
    parser.add_argument("--dry-run", action="store_true", help="count only, delete nothing")
    parser.add_argument("--purge-prompts", action="store_true",
                        help="blank stored raw prompts/outputs (privacy one-time action)")
    args = parser.parse_args()
    setup_logging()
    asyncio.run(cleanup(dry_run=args.dry_run, purge_prompts=args.purge_prompts))
