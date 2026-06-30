"""
API Authentication & Authorization Middleware.

Provides Bearer token authentication for all API endpoints.
Tokens are JWT-based, with secret persisted to disk on first run.
"""

from __future__ import annotations

import logging
import os
import secrets
from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

logger = logging.getLogger(__name__)

_SECRET_FILE = Path("~/.config/urban-hs/jwt_secret").expanduser()
_security = HTTPBearer(auto_error=False)


def _load_or_create_secret() -> str:
    """Load JWT secret from disk, or generate and persist a new one."""
    if _SECRET_FILE.exists():
        secret = _SECRET_FILE.read_text().strip()
        if secret:
            return secret

    secret = secrets.token_urlsafe(48)
    try:
        _SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        _SECRET_FILE.write_text(secret)
        os.chmod(_SECRET_FILE, 0o600)
        logger.info("Generated new JWT secret", path=str(_SECRET_FILE))
    except OSError as exc:
        logger.warning("Could not persist jwt_secret to disk, using ephemeral", error=str(exc))
    return secret


_jwt_secret: Optional[str] = None


def get_jwt_secret() -> str:
    global _jwt_secret
    if _jwt_secret is None:
        _jwt_secret = _load_or_create_secret()
    return _jwt_secret


def create_access_token(
    subject: str,
    expires_minutes: int = 60,
    algorithm: str = "HS256",
) -> str:
    """Create a signed JWT access token."""
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + timedelta(minutes=expires_minutes),
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=algorithm)


def decode_access_token(token: str, algorithm: str = "HS256") -> dict:
    """Decode and validate a JWT access token."""
    return jwt.decode(token, get_jwt_secret(), algorithms=[algorithm])


async def verify_bearer(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_security),
) -> str:
    """FastAPI dependency: verify Bearer token, return subject."""
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_access_token(credentials.credentials)
        return payload.get("sub", "")
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid or expired token: {exc}",
            headers={"WWW-Authenticate": "Bearer"},
        )


def require_auth():
    """Return a FastAPI dependency that enforces Bearer authentication."""
    return Depends(verify_bearer)
