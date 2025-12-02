from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple
import uuid

from passlib.hash import argon2
import jwt
from fastapi import HTTPException, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .config import (
    JWT_SECRET_KEY,
    JWT_ALGORITHM,
    JWT_EXPIRATION_MINUTES,
    JWT_REFRESH_EXPIRATION_DAYS,
    ISSUER,
    AUDIENCE
)

security = HTTPBearer()


def hash_password(password: str) -> str:
    """
    Hash a password using Argon2.
    
    Args:
        password: Plain text password
        
    Returns:
        Hashed password string
    """
    return argon2.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a password against its hash.
    
    Args:
        plain_password: Plain text password to verify
        hashed_password: Hashed password to compare against
        
    Returns:
        True if password matches, False otherwise
    """
    try:
        return argon2.verify(plain_password, hashed_password)
    except Exception:
        return False


def create_tokens(data: Dict[str, str]) -> Tuple[str, str]:
    """
    Create both access and refresh JWT tokens.
    
    Args:
        data: Dictionary containing user claims (sub, user_id, role)
        
    Returns:
        Tuple of (access_token, refresh_token)
    """
    now = datetime.now(timezone.utc)
    
    # Create access token (short-lived)
    access_payload = data.copy()
    access_payload.update({
        "exp": now + timedelta(minutes=JWT_EXPIRATION_MINUTES),
        "iat": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "type": "access"
    })
    access_token = jwt.encode(access_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    # Create refresh token (long-lived)
    refresh_payload = data.copy()
    refresh_payload.update({
        "exp": now + timedelta(days=JWT_REFRESH_EXPIRATION_DAYS),
        "iat": now,
        "iss": ISSUER,
        "aud": AUDIENCE,
        "type": "refresh",
        "jti": str(uuid.uuid4())  # Unique token ID for potential blacklisting
    })
    refresh_token = jwt.encode(refresh_payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return access_token, refresh_token


def verify_token(credentials: HTTPAuthorizationCredentials = Security(security)) -> Dict[str, str]:
    """
    Verify and decode JWT access token.
    
    This function is used as a FastAPI dependency to protect routes.
    
    Args:
        credentials: HTTP Bearer token from request header
        
    Returns:
        Decoded token payload
        
    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        token = credentials.credentials
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        # Verify it's an access token (not refresh)
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
            
        return payload
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")
