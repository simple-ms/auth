from datetime import datetime, timedelta, timezone
from passlib.hash import argon2
import jwt
from fastapi.security import HTTPBearer
from .config import JWT_SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_MINUTES, ISSUER, AUDIENCE
import uuid

security = HTTPBearer()

def hash_password(password: str) -> str:
    """Hash a password using Argon2"""
    return argon2.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    return argon2.verify(plain_password, hashed_password)

def create_access_token(data: dict) -> str:
    """Create a JWT access token"""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=JWT_EXPIRATION_MINUTES)

    to_encode.update({
        "exp": expire,                  # Expiration time
        "iat": now,                     # Issued At time
        "iss": ISSUER,                  # Issuer (Who created this?)
        "aud": AUDIENCE,                # Audience (Who is this for?)
        "jti": str(uuid.uuid4()),       # Unique Token ID (For blacklisting later)
        "type": "access"                # Token type
    })

    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt

# def create_refresh_token(data: dict) -> str:
#     """Create a JWT refresh token"""
#     to_encode = data.copy()
#     now = datetime.now(timezone.utc)
#     expire = now + timedelta(days=7)
    
#     to_encode.update({
#         "exp": expire,                  # Expiration time
#         "iat": now,                     # Issued At time
#         "iss": ISSUER,                  # Issuer (Who created this?)
#         "aud": AUDIENCE,                # Audience (Who is this for?)
#         "jti": str(uuid.uuid4()),       # Unique Token ID (For blacklisting later)
#         "type": "refresh"               # Token type
#     })

#     encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
#     return encoded_jwt
