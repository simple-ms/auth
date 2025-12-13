"""
CSRF Protection Middleware

Validates CSRF tokens for state-changing requests (POST, PUT, PATCH, DELETE).
"""
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from typing import Set
import secrets
import hashlib


class CSRFMiddleware(BaseHTTPMiddleware):
    """
    CSRF Protection Middleware
    
    Validates X-CSRF-Token header for state-changing requests.
    Exempt paths can be configured (e.g., /auth/login, /auth/register).
    """
    
    def __init__(
        self,
        app,
        exempt_paths: Set[str] = None,
        header_name: str = "X-CSRF-Token"
    ):
        super().__init__(app)
        self.exempt_paths = exempt_paths or {
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
            "/docs/auth",
            "/openapi.json/auth",
            "/redoc/auth",
            "/health"
        }
        self.header_name = header_name
        self.state_changing_methods = {"POST", "PUT", "PATCH", "DELETE"}
    
    async def dispatch(self, request: Request, call_next):
        # Skip CSRF check for safe methods (GET, HEAD, OPTIONS)
        if request.method not in self.state_changing_methods:
            return await call_next(request)
        
        # Skip CSRF check for exempt paths
        path = request.url.path
        if path in self.exempt_paths or path.startswith("/docs") or path.startswith("/openapi"):
            return await call_next(request)
        
        # Get CSRF token from header
        csrf_token = request.headers.get(self.header_name)
        
        if not csrf_token:
            raise HTTPException(
                status_code=403,
                detail="CSRF token missing. Include X-CSRF-Token header."
            )
        
        # Validate CSRF token
        # In production, you might want to validate against a stored token
        # For now, we just check that it exists and has minimum length
        if len(csrf_token) < 16:
            raise HTTPException(
                status_code=403,
                detail="Invalid CSRF token"
            )
        
        # Token is valid, proceed with request
        response = await call_next(request)
        return response


def generate_csrf_token() -> str:
    """
    Generate a secure CSRF token
    
    Returns:
        str: 32-byte hex token
    """
    return secrets.token_hex(32)


def validate_csrf_token(token: str, expected: str = None) -> bool:
    """
    Validate CSRF token
    
    Args:
        token: Token to validate
        expected: Expected token value (optional)
    
    Returns:
        bool: True if valid
    """
    if not token or len(token) < 16:
        return False
    
    # If expected token provided, compare securely
    if expected:
        return secrets.compare_digest(token, expected)
    
    # Otherwise just check format
    return True
