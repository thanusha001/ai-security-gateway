"""Request-scoped context variables (request_id, user_id).

Context vars propagate into any task spawned from the request handler, so
pipeline events fired deep in the pipeline automatically carry request_id.
"""
from __future__ import annotations

import uuid
from contextvars import ContextVar

request_id_var: ContextVar[str | None] = ContextVar("request_id", default=None)
user_id_var: ContextVar[int | None] = ContextVar("user_id", default=None)
stage_var: ContextVar[str | None] = ContextVar("stage", default=None)


def new_request_id() -> str:
    return uuid.uuid4().hex


def get_request_id() -> str | None:
    return request_id_var.get()


def get_user_id() -> int | None:
    return user_id_var.get()


def get_stage() -> str | None:
    return stage_var.get()


def set_stage(stage: str) -> None:
    stage_var.set(stage)
