"""PhantomFeed — Authentication API Routes"""

import time
from collections import defaultdict
from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request
from pydantic import BaseModel, field_validator

from auth.auth import verify_password, create_access_token, get_current_user, decode_token
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

_bearer = HTTPBearer(auto_error=False)

router = APIRouter()

# AC-7 brute-force lockout: 5 failures → 15-minute lockout per username
_MAX_ATTEMPTS = 5
_LOCKOUT_SECONDS = 900  # 15 minutes
_attempts: dict = defaultdict(list)  # username -> [timestamp, ...]


def _check_lockout(username: str) -> None:
    now = time.monotonic()
    recent = [t for t in _attempts[username] if now - t < _LOCKOUT_SECONDS]
    _attempts[username] = recent
    if len(recent) >= _MAX_ATTEMPTS:
        remaining = int(_LOCKOUT_SECONDS - (now - recent[0]))
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account locked after too many failed attempts. Try again in {remaining}s.",
        )


def _record_failure(username: str) -> None:
    _attempts[username].append(time.monotonic())


def _clear_failures(username: str) -> None:
    _attempts.pop(username, None)


class LoginRequest(BaseModel):
    username: str
    password: str

    @field_validator("username", "password")
    @classmethod
    def not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("cannot be empty")
        if len(v) > 256:
            raise ValueError("too long")
        return v


@router.post("/login", summary="Login and receive a JWT token")
async def login(req: LoginRequest, request: Request):
    from db import database as db

    from db.audit_log import log_event

    _check_lockout(req.username)
    ip = request.client.host if request.client else None

    user = await db.get_user_by_username(req.username)
    if not user or not verify_password(req.password, user["password_hash"]):
        _record_failure(req.username)
        await log_event(
            "login_failure",
            username=req.username,
            method="POST",
            path="/auth/login",
            status_code=401,
            ip_address=ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    _clear_failures(req.username)
    token = create_access_token({
        "sub": user["id"],
        "role": user["role"],
        "username": user["username"],
        "token_version": user.get("token_version") or 0,
    })
    await log_event(
        "login_success",
        user_id=user["id"],
        username=user["username"],
        method="POST",
        path="/auth/login",
        status_code=200,
        ip_address=ip,
    )
    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "display_name": user["username"],
        "client_id": user.get("client_id"),
    }


@router.get("/me", summary="Get the currently authenticated user")
async def me(user: dict = Depends(get_current_user)):
    return {
        "id": user["id"],
        "username": user["username"],
        "role": user["role"],
        "client_id": user.get("client_id"),
    }


@router.post("/logout", summary="Revoke the current JWT token")
async def logout(
    request: Request,
    user: dict = Depends(get_current_user),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
):
    """Add the token's jti to the denylist so it cannot be reused before expiry."""
    from db import database as db
    from db.audit_log import log_event
    from datetime import datetime

    if credentials:
        payload = decode_token(credentials.credentials)
        jti = payload.get("jti")
        exp = payload.get("exp")
        if jti and exp:
            from datetime import timezone as _tz
            expires_at = datetime.fromtimestamp(exp, tz=_tz.utc).replace(tzinfo=None).isoformat()
            await db.revoke_token(jti, user["id"], expires_at)

    ip = request.client.host if request.client else None
    await log_event(
        "logout",
        user_id=user["id"],
        username=user.get("username"),
        method="POST",
        path="/auth/logout",
        status_code=200,
        ip_address=ip,
    )
    return {"status": "logged_out"}
