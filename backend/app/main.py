"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.routes import api_router
from app.core.config import settings
from app.core.errors import GatewayError, gateway_error_handler, unhandled_error_handler
from app.core.logging import setup_logging
from app.core.middleware import (
    RequestContextMiddleware,
    RequestSizeLimitMiddleware,
    SecureHeadersMiddleware,
)
from app.core.request_context import get_request_id

setup_logging()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup: nothing heavy — embeddings load lazily on first use
    yield


app = FastAPI(
    title="AI Security Gateway",
    description=(
        "Security gateway for LLM & RAG applications: input security, risk "
        "engine, policy engine, RAG context security, LLM observability, "
        "output security, and full audit trail."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    openapi_url="/openapi.json",
)

# middleware order: outermost first
app.add_middleware(RequestSizeLimitMiddleware, max_body_mb=settings.max_upload_size_mb + 5)
app.add_middleware(SecureHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
)

# error handling: every error in the standard envelope
app.add_exception_handler(GatewayError, gateway_error_handler)
app.add_exception_handler(Exception, unhandled_error_handler)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": {
            "code": "VALIDATION_ERROR",
            "message": "Request validation failed",
            "request_id": getattr(request.state, "request_id", None) or get_request_id(),
            "details": {"errors": exc.errors()[:10]},
        }},
    )


app.include_router(api_router)
