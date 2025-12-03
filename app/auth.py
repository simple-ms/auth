from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple
import uuid

from passlib.hash import argon2
import jwt
from fastapi import HTTPException, status

from .config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES,
    JWT_REFRESH_EXPIRATION_DAYS,
    ISSUER,
    AUDIENCE
)

def hash_password(password: str) -> str:
    """Hash a password using Argon2."""
    return argon2.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return argon2.verify(plain_password, hashed_password)
    except Exception:
        return False

def create_tokens(data: Dict[str, str]) -> Tuple[str, str]:
    """Create Access and Refresh tokens with distinct types."""
    now = datetime.now(timezone.utc)
    
    base_payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
    }
    
    # 1. Create Access Token
    access_payload = base_payload.copy()
    access_payload.update(data)
    access_payload.update({
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "type": "access" # Explicit type
    })
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    # 2. Create Refresh Token
    refresh_payload = base_payload.copy()
    refresh_payload.update(data)
    refresh_payload.update({
        "exp": now + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),
        "type": "refresh", # Explicit type
        "jti": str(uuid.uuid4())
    })
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return access_token, refresh_token

def _decode_jwt(token: str) -> Dict:
    """
    Internal Helper: Only checks cryptographic signature and expiration.
    Does NOT check token type.
    """
    try:
        return jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token"
        )

def verify_access_token(token: str) -> Dict:
    """
    STRICTLY verifies that the token is an ACCESS token.
    """
    payload = _decode_jwt(token)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token type: Access token required"
        )
    return payload

def verify_refresh_token(token: str) -> Dict:
    """
    STRICTLY verifies that the token is a REFRESH token.
    """
    payload = _decode_jwt(token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, 
            detail="Invalid token type: Refresh token required"
        )
    return payload