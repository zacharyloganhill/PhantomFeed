"""
PhantomFeed — JWT Authentication Utilities

Uses python-jose for JWT and passlib[bcrypt] for password hashing.
Admin user is seeded automatically from ADMIN_PASSWORD env var on startup.
"""

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
    return jwt.encode(to_encode, config.SECRET_KEY, algorithm=config.ALGORITHM)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(token, config.SECRET_KEY, algorithms=[config.ALGORITHM])
    except JWTError:
        return {}


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> dict:
    from db import database as db

    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    payload = decode_token(credentials.credentials)
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = await db.get_user_by_id(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


async def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


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
