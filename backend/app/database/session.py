"""Async SQLAlchemy engine/session with timeout and health probe."""
from __future__ import annotations

import asyncio
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

engine = create_async_engine(
    settings.database_url,
    echo=settings.db_echo,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
    connect_args={"timeout": settings.database_timeout_seconds},
)

SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


async def get_db() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency yielding a database session."""
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_database() -> bool:
    """Cheap connectivity probe used by /health."""
    try:
        async with asyncio.timeout(settings.database_timeout_seconds):
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        return True
    except (OSError, asyncio.TimeoutError, Exception):
        return False
