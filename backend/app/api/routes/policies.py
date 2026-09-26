"""Policy API routes (ADMIN only for writes; AUDITOR/USER read)."""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import Role, require_roles
from app.database.models import AuditLog
from app.database.session import get_db
from app.schemas.policies import PolicyCreate, PolicyOut, PolicyUpdate
from app.services.policy_service import (
    activate_policy,
    create_policy,
    deactivate_policy,
    get_policy,
    list_policies,
    update_policy,
)

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


def _policy_out(p) -> PolicyOut:
    return PolicyOut(
        id=p.id, name=p.name, version=p.version, description=p.description,
        configuration=p.configuration_json, is_active=p.is_active,
        created_at=p.created_at.isoformat() if p.created_at else None,
        updated_at=p.updated_at.isoformat() if p.updated_at else None,
    )


@router.get("", response_model=list[PolicyOut])
async def get_policies(
    user=Depends(require_roles(Role.ADMIN, Role.AUDITOR)),
    db: AsyncSession = Depends(get_db),
):
    return [_policy_out(p) for p in await list_policies(db)]


@router.post("", response_model=PolicyOut, status_code=201)
async def post_policy(
    body: PolicyCreate,
    user=Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    policy = await create_policy(
        db, name=body.name, description=body.description,
        configuration=body.configuration.model_dump(), actor_id=user.id,
    )
    db.add(AuditLog(user_id=user.id, action="policy_create", resource_type="policy",
                    resource_id=str(policy.id),
                    details_json={"name": policy.name, "version": policy.version}))
    await db.commit()
    return _policy_out(policy)


@router.put("/{policy_id}", response_model=PolicyOut)
async def put_policy(
    policy_id: int,
    body: PolicyUpdate,
    user=Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    policy = await update_policy(
        db, policy_id, description=body.description,
        configuration=body.configuration.model_dump() if body.configuration else None,
        actor_id=user.id,
    )
    db.add(AuditLog(user_id=user.id, action="policy_update", resource_type="policy",
                    resource_id=str(policy.id), details_json={"version": policy.version}))
    await db.commit()
    return _policy_out(policy)


@router.post("/{policy_id}/activate", response_model=PolicyOut)
async def activate(
    policy_id: int,
    user=Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    policy = await activate_policy(db, policy_id, actor_id=user.id)
    db.add(AuditLog(user_id=user.id, action="policy_activate", resource_type="policy",
                    resource_id=str(policy.id),
                    details_json={"name": policy.name, "version": policy.version}))
    await db.commit()
    return _policy_out(policy)


@router.post("/{policy_id}/deactivate", response_model=PolicyOut)
async def deactivate(
    policy_id: int,
    user=Depends(require_roles(Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    policy = await deactivate_policy(db, policy_id, actor_id=user.id)
    db.add(AuditLog(user_id=user.id, action="policy_deactivate", resource_type="policy",
                    resource_id=str(policy.id), details_json=None))
    await db.commit()
    return _policy_out(policy)
