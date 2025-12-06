from .health import router as health_router
from .auth import router as auth_router
from .user import router as user_router

__all__ = ["health_router", "auth_router", "user_router"]

