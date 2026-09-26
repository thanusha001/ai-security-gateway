"""Chat API route — the protected gateway entrypoint."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.security import Role, require_roles
from app.core.config import settings
from app.core.rate_limit import chat_limiter
from app.database.models import AuditLog, RateLimitEvent
from app.database.session import get_db
from app.schemas.chat import ChatRequest
from app.services.chat_service import execute_chat_request

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])


@router.post("")
async def chat(
    request: Request,
    body: ChatRequest,
    user=Depends(require_roles(Role.USER, Role.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    client_ip = request.client.host if request.client else "unknown"
    limiter_key = f"user:{user.id}"
    allowed, remaining, retry_after = chat_limiter.check(limiter_key)

    db.add(RateLimitEvent(
        user_id=user.id, endpoint="/api/v1/chat",
        client_identifier=limiter_key, allowed=allowed,
    ))
    await db.flush()

    if not allowed:
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail={
                "code": "RATE_LIMITED",
                "message": f"Rate limit exceeded; retry in {retry_after}s",
                "details": {"retry_after_seconds": retry_after},
            },
            headers={"Retry-After": str(retry_after)},
        )

    result = await execute_chat_request(
        db, user_id=user.id, message=body.message,
        session_id=body.session_id, top_k=body.top_k,
    )

    if "error" in result:
        code = result["error"]["code"]
        status_map = {"LLM_UNAVAILABLE": 503, "LLM_TIMEOUT": 504, "LLM_ERROR": 502,
                      "INTERNAL_ERROR": 500}
        raise HTTPException(
            status_code=status_map.get(code, 500),
            detail={"code": code, "message": result["error"]["message"],
                    "request_id": result["error"]["request_id"]},
        )

    return result
