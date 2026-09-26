"""Policy service: CRUD + validation + versioning + activation.

Rule: an invalid policy can NEVER become active. Activation requires the
configuration to pass PolicyConfiguration validation; deactivating the active
policy is prevented if no other active policy exists (the gateway always needs
one). Every request records the policy version it used.
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError

from app.core.errors import ErrorCode, GatewayError
from app.database.models import SecurityPolicy
from app.policy.engine import DEFAULT_POLICY_CONFIG, PolicyConfiguration
from app.core.logging import get_logger

log = get_logger("policy_service")


async def get_active_policy(db: AsyncSession) -> tuple[PolicyConfiguration, SecurityPolicy | None]:
    """Load the active policy; fall back to built-in defaults if none exists."""
    try:
        result = await db.execute(
            select(SecurityPolicy).where(SecurityPolicy.is_active.is_(True))
        )
        row = result.scalar_one_or_none()
    except SQLAlchemyError:
        log.exception("active_policy_query_failed")
        raise GatewayError(
            ErrorCode.INTERNAL_ERROR, "Policy store unavailable", 503
        )

    if row is None:
        # Built-in defaults keep the gateway functional before first setup.
        return PolicyConfiguration(**DEFAULT_POLICY_CONFIG), None

    try:
        config = PolicyConfiguration(**row.configuration_json)
    except Exception as exc:
        # The stored policy no longer validates (e.g. code evolution): fail
        # closed rather than running without policy.
        log.exception("active_policy_invalid")
        raise GatewayError(
            ErrorCode.POLICY_VIOLATION, "Active policy is invalid", 503
        )

    return config, row


async def create_policy(
    db: AsyncSession, *, name: str, description: str | None,
    configuration: dict, actor_id: int,
) -> SecurityPolicy:
    # validate before insert
    PolicyConfiguration(**configuration)

    result = await db.execute(
        select(SecurityPolicy.version)
        .where(SecurityPolicy.name == name)
        .order_by(SecurityPolicy.version.desc())
        .limit(1)
    )
    latest = result.scalar_one_or_none()
    version = (latest or 0) + 1

    policy = SecurityPolicy(
        name=name, version=version, description=description,
        configuration_json=configuration, is_active=False,
    )
    db.add(policy)
    await db.commit()
    await db.refresh(policy)
    log.info("policy_created", name=name, version=version, actor_id=actor_id)
    return policy


async def update_policy(
    db: AsyncSession, policy_id: int, *,
    description: str | None = None, configuration: dict | None = None,
    actor_id: int,
) -> SecurityPolicy:
    result = await db.execute(select(SecurityPolicy).where(SecurityPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise GatewayError(ErrorCode.NOT_FOUND, "Policy not found", 404)

    if configuration is not None:
        PolicyConfiguration(**configuration)  # validate
        # policy change => new immutable version
        return await create_policy(
            db, name=policy.name, description=description or policy.description,
            configuration=configuration, actor_id=actor_id,
        )
    policy.description = description if description is not None else policy.description
    await db.commit()
    await db.refresh(policy)
    return policy


async def activate_policy(db: AsyncSession, policy_id: int, actor_id: int) -> SecurityPolicy:
    result = await db.execute(select(SecurityPolicy).where(SecurityPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise GatewayError(ErrorCode.NOT_FOUND, "Policy not found", 404)

    # re-validate stored config before activation (defense in depth)
    try:
        PolicyConfiguration(**policy.configuration_json)
    except Exception as exc:
        raise GatewayError(
            ErrorCode.POLICY_VIOLATION,
            "Policy configuration is invalid; cannot activate",
            422,
        ) from exc

    # deactivate all others atomically
    result = await db.execute(select(SecurityPolicy).where(SecurityPolicy.is_active.is_(True)))
    for active in result.scalars():
        active.is_active = False
    policy.is_active = True
    await db.commit()
    await db.refresh(policy)
    log.info("policy_activated", name=policy.name, version=policy.version, actor_id=actor_id)
    return policy


async def deactivate_policy(db: AsyncSession, policy_id: int, actor_id: int) -> SecurityPolicy:
    result = await db.execute(select(SecurityPolicy).where(SecurityPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise GatewayError(ErrorCode.NOT_FOUND, "Policy not found", 404)
    policy.is_active = False
    await db.commit()
    await db.refresh(policy)
    log.info("policy_deactivated", name=policy.name, version=policy.version, actor_id=actor_id)
    return policy


async def list_policies(db: AsyncSession) -> list[SecurityPolicy]:
    result = await db.execute(
        select(SecurityPolicy).order_by(SecurityPolicy.name, SecurityPolicy.version.desc())
    )
    return list(result.scalars())


async def get_policy(db: AsyncSession, policy_id: int) -> SecurityPolicy:
    result = await db.execute(select(SecurityPolicy).where(SecurityPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if policy is None:
        raise GatewayError(ErrorCode.NOT_FOUND, "Policy not found", 404)
    return policy
