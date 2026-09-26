"""First-startup bootstrap.

- creates the pgvector extension (idempotent)
- creates the bootstrap admin from env (ADMIN_EMAIL/ADMIN_PASSWORD)
- seeds the default security policy if none exists

Run once via `python -m app.bootstrap` (Docker compose does this automatically).
"""
from __future__ import annotations

import asyncio

from sqlalchemy import text

from app.core.config import settings
from app.core.crypto import hash_password
from app.core.logging import setup_logging, get_logger
from app.database.models import SecurityPolicy, User
from app.database.session import SessionLocal, engine
from app.policy.engine import DEFAULT_POLICY_CONFIG

log = get_logger("bootstrap")


async def bootstrap() -> None:
    setup_logging()
    async with engine.begin() as conn:
        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))

    async with SessionLocal() as db:
        admin = (
            await db.execute(text("SELECT id FROM users WHERE email = :email"),
                             {"email": settings.admin_email.lower()})
        ).scalar()
        if admin is None:
            db.add(User(
                email=settings.admin_email.lower(),
                password_hash=hash_password(settings.admin_password),
                role="ADMIN",
            ))
            log.info("bootstrap_admin_created", email=settings.admin_email)

        policy_count = (
            await db.execute(text("SELECT count(*) FROM security_policies"))
        ).scalar()
        if not policy_count:
            db.add(SecurityPolicy(
                name="default-security-policy",
                version=1,
                description="Built-in default policy (v1 thresholds, pending evaluation)",
                configuration_json=DEFAULT_POLICY_CONFIG,
                is_active=True,
            ))
            log.info("bootstrap_policy_created")

        await db.commit()
    await engine.dispose()
    log.info("bootstrap_complete")


if __name__ == "__main__":
    asyncio.run(bootstrap())
