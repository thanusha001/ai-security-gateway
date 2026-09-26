# =============================================================================
# AI Security Gateway — single root Dockerfile
#
# Multi-stage build: one build context, two deployable targets.
#   - target "frontend": React/Vite build served by nginx (API proxy + SSE)
#   - target "backend":  FastAPI + uvicorn (non-root)
#
# Build individually:
#   docker build --target backend  -t gateway-backend  .
#   docker build --target frontend -t gateway-frontend .
# Or simply: docker compose up --build
# =============================================================================
# syntax=docker/dockerfile:1

# --- Stage 1: frontend build -------------------------------------------------
FROM node:22-alpine AS frontend-build

WORKDIR /app/frontend

# Dependencies first for layer caching (package.json + lockfile only)
COPY frontend/package.json frontend/package-lock.json ./
# Aggressive retry policy: flaky networks (VPN/proxy) can cut bulk tarball
# transfers mid-stream; npm re-fetches rather than failing the build.
RUN npm config set fetch-retries 10 \
 && npm config set fetch-retry-mintimeout 20000 \
 && npm config set fetch-retry-maxtimeout 120000 \
 && npm config set fetch-timeout 600000 \
 && (npm ci || npm install)

# Source + production build (tsc -b && vite build)
COPY frontend/ ./
RUN npm run build

# --- Stage 2: frontend serve (nginx) ------------------------------------------
FROM nginx:1.27-alpine AS frontend

# Shared nginx config (SPA fallback, /api proxy to backend:8000, SSE no-buffer)
COPY docker/nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=frontend-build /app/frontend/dist /usr/share/nginx/html

EXPOSE 80

# --- Stage 3: backend (FastAPI + uvicorn) --------------------------------------
FROM python:3.12-slim AS backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Non-root user
RUN groupadd -r gateway && useradd -r -g gateway gateway

WORKDIR /app

# Dependencies first for layer caching
COPY backend/requirements.txt .
# Aggressive retry policy: flaky networks (VPN/proxy) can cut bulk wheel
# transfers mid-stream; pip retries each file instead of failing the build.
ENV PIP_RETRIES=10 \
    PIP_TIMEOUT=60
#
# sentence-transformers pulls in torch (multi-GB of wheels). The default
# Docker image installs everything EXCEPT it — the API is explicitly designed
# to run without it (RAG retrieval degrades, /health shows
# embedding_model: unavailable; see requirements.txt comment and README).
# Opt into the full install with:  --build-arg FULL_EMBEDDINGS=true
#
ARG FULL_EMBEDDINGS=false
RUN if [ "$FULL_EMBEDDINGS" = "true" ]; then \
        pip install --no-cache-dir -r requirements.txt; \
    else \
        grep -vE '^\s*sentence-transformers' requirements.txt > /tmp/requirements.txt; \
        pip install --no-cache-dir -r /tmp/requirements.txt; \
    fi

# Application code (backend/ contents: app/, alembic/, alembic.ini, pytest.ini)
COPY backend/ .

USER gateway

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
