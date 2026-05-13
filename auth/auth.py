"""
PhantomFeed — JWT Authentication Utilities

Uses python-jose for JWT and passlib[bcrypt] for password hashing.
Admin user is seeded automatically from ADMIN_PASSWORD env var on startup.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from passlib.context import CryptContext

import config

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer_scheme = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc).replace(tzinfo=None) + (
        expires_delta or timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode["exp"] = expire
    to_encode.setdefault("jti", str(uuid.uuid4()))  # unique ID for per-token revocation
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
    except JWTError:
        return {}


async def _validate_decoded_token(payload: dict) -> dict:
    """
    Shared validation after a token has been decoded:
    1. sub claim present
    2. jti not in denylist
    3. user exists in DB
    4. token_version matches current DB value (catches admin force-logout)
    """
    from db import database as db

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    jti = payload.get("jti")
    if jti and await db.is_token_revoked(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has been revoked")

    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    token_ver = payload.get("token_version", 0)
    db_ver = user.get("token_version") or 0
    if token_ver != db_ver:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session invalidated")

    return user


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    payload = decode_token(credentials.credentials)
    return await _validate_decoded_token(payload)


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def require_client_access(user: dict, client_id: str) -> None:
    """Raise 403 if a non-admin user tries to access another client's data."""
    if user.get("role") != "admin" and user.get("client_id") != client_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")


async def seed_admin_user():
    """Create the admin user if it doesn't already exist."""
    from db import database as db

    existing = await db.get_user_by_username("admin")
    if not existing:
        hashed = hash_password(config.ADMIN_PASSWORD)
        await db.create_user(
            username="admin",
            password_hash=hashed,
            role="admin",
            client_id=None,
        )
