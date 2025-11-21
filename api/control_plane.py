"""FastAPI control plane for policy updates, status, and token validation."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, TypeAlias

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from api import admin
from auth.ztna_token_validator import ZTNATokenValidator
from logging_config import configure_logging

configure_logging()
logger = logging.getLogger(__name__)
app = FastAPI(title="SASE Control Plane", version="0.2.0")

LogEntry: TypeAlias = Dict[str, object]
LOG_STORE: list[LogEntry] = []
LOG_PATH = Path(__file__).resolve().parents[1] / "streamlit_logs" / "gateway.log"


class PolicyUpdate(BaseModel):
    """Payload model for uploading a full policy document."""

    policies: dict[str, object] = Field(..., description="Full policy document to persist")


class RegisterUser(BaseModel):
    """Register a new user and provision a token."""

    username: str
    token: str


class TokenVerify(BaseModel):
    """Token verification request model."""

    token: str


@app.post("/policy/update")
def update_policy(payload: PolicyUpdate) -> dict[str, str]:
    """Replace the policy file with the posted document."""

    admin.save_policies(payload.policies)
    logger.info("Policies updated via control plane")
    return {"status": "ok"}


@app.get("/logs")
def get_logs(limit: int = 50) -> list[LogEntry]:
    """Return the most recent normalized logs from disk (and memory fallback)."""

    if limit <= 0:
        raise HTTPException(status_code=400, detail="limit must be positive")

    entries: list[LogEntry] = []
    if LOG_PATH.exists():
        with LOG_PATH.open("r", encoding="utf-8") as handle:
            for line in handle:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not entries:
        entries = LOG_STORE
    return entries[-limit:]


@app.post("/user/register")
def register_user(user: RegisterUser) -> dict[str, str]:
    """Register a user with a token and baseline policy defaults."""

    policies = admin.load_policies()
    users = policies.setdefault("users", {})
    users[user.username] = {
        "allowed_categories": ["Business", "Productivity"],
        "blocked_categories": ["Malware"],
        "allowed_destinations": [],
        "device_trust_required": True,
        "allow_all_if_no_match": False,
    }
    tokens = policies.setdefault("tokens", {})
    tokens[user.username] = user.token
    admin.save_policies(policies)
    logger.info("Registered user", extra={"user": user.username})
    return {"status": "registered", "user": user.username}


@app.post("/token/verify")
def token_verify(payload: TokenVerify) -> dict[str, str]:
    """Validate a Zero Trust token."""

    validator = ZTNATokenValidator()
    result = validator.validate(payload.token)
    if not result.valid or result.user is None:
        raise HTTPException(status_code=401, detail=result.reason)
    return {"user": result.user, "status": "valid"}


@app.get("/status")
def status() -> JSONResponse:
    """Health and config status endpoint."""

    config_path = Path(__file__).resolve().parents[1] / "config" / "policies.yaml"
    health = {"status": "healthy", "policies_path": str(config_path), "log_path": str(LOG_PATH)}
    return JSONResponse(health)
