"""
Auth Service - Authentication and Authorization Microservice

This is the main entry point for the Auth service.
All routes are defined in views/ and registered via routes.py
"""
from fastapi import FastAPI
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .routes import register_routes
from .middleware import CSRFMiddleware

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization microservice",
    version="1.0.0",
    docs_url="/docs/auth",
    openapi_url="/openapi.json/auth",
    redoc_url="/redoc/auth"
)

# Add rate limiter to app state and error handler
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Add CSRF protection middleware
# Exempt login, register, and refresh endpoints (they don't have CSRF token yet)
app.add_middleware(
    CSRFMiddleware,
    exempt_paths={
        "/auth/login",
        "/auth/register", 
        "/auth/refresh",
        "/docs/auth",
        "/openapi.json/auth",
        "/redoc/auth",
        "/health"
    }
)

# NOTE: CORS is handled by nginx gateway - no CORS middleware here

# Register all routes
register_routes(app)
