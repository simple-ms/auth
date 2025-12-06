from typing import Dict
from fastapi import Depends, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from .database import get_db
from .models import User
from .repository import UserRepository
from .services import AuthService

security = HTTPBearer()


async def get_user_repository(db: AsyncSession = Depends(get_db)) -> UserRepository:
    """Dependency to get UserRepository instance."""
    return UserRepository(db)


async def get_auth_service(
    user_repository: UserRepository = Depends(get_user_repository)
) -> AuthService:
    """Dependency to get AuthService instance."""
    return AuthService(user_repository)


async def get_token_payload(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> Dict:
    """
    Extracts token and ensures it is a valid ACCESS token.
    Used for lightweight validation (like Nginx checks).
    """
    token = credentials.credentials
    return AuthService.verify_access_token(token)


async def get_current_user(
    payload: Dict = Depends(get_token_payload),
    auth_service: AuthService = Depends(get_auth_service)
) -> User:
    """
    Validates Access Token AND ensures user exists in DB.
    Used for /me, /password, etc.
    """
    user_id = payload.get("user_id")
    return await auth_service.get_current_user(user_id)

