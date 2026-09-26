"""Auth API routes."""
from __future__ import annotations

from pydantic import BaseModel, EmailStr, Field

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import Role, create_access_token, get_current_user
from app.core.crypto import hash_password, verify_password
from app.database.models import AuditLog, User
from app.database.session import get_db
from app.schemas.auth import RegisterRequest, TokenResponse, UserOut

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


class LoginBody(BaseModel):
    # plain str: login is an exact-match lookup, and EmailStr would reject
    # reserved dev domains like .local used for the bootstrap admin.
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=128)


@router.post("/register", response_model=UserOut, status_code=201)
async def register(body: RegisterRequest, db: AsyncSession = Depends(get_db)) -> UserOut:
    existing = (
        await db.execute(select(User).where(User.email == body.email.lower()))
    ).scalar_one_or_none()
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"code": "AUTHENTICATION_FAILED", "message": "Email already registered"},
        )
    user = User(
        email=body.email.lower(),
        password_hash=hash_password(body.password),
        role=Role.USER.value,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return UserOut.model_validate(user)


@router.post("/login", response_model=TokenResponse)
async def login(request: Request, body: LoginBody, db: AsyncSession = Depends(get_db)) -> TokenResponse:
    user = (
        await db.execute(select(User).where(User.email == body.email.lower()))
    ).scalar_one_or_none()
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_FAILED", "message": "Invalid email or password"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "AUTHENTICATION_FAILED", "message": "Account is inactive"},
        )
    db.add(AuditLog(
        user_id=user.id, action="login", resource_type="user", resource_id=str(user.id),
        ip_address=request.client.host if request.client else None,
    ))
    await db.commit()
    token = create_access_token(user.id, user.email, user.role)
    return TokenResponse(access_token=token, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
async def me(user=Depends(get_current_user)) -> UserOut:
    return UserOut.model_validate(user)
