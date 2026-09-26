"""API router aggregation."""
from fastapi import APIRouter

from app.api.routes import auth, chat, documents, events, health, policies

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(chat.router)
api_router.include_router(documents.router)
api_router.include_router(policies.router)
api_router.include_router(events.router)
api_router.include_router(health.router)
