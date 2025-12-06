from fastapi import APIRouter, Depends, Request

from ..models.user import User
from ..schemas.auth import PasswordChange
from ..schemas.user import UserResponse
from ..services import AuthService
from ..dependencies import get_auth_service, get_current_user

router = APIRouter(prefix="/auth", tags=["User"])


@router.put("/password")
async def change_password(
    request: Request,
    password_data: PasswordChange,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Change password for authenticated user.
    
    Rate limited to 3 requests per minute per IP address.
    """
    return await auth_service.change_password(
        current_user, 
        password_data.old_password, 
        password_data.new_password
    )


@router.delete("/me")
async def delete_account(
    request: Request,
    current_user: User = Depends(get_current_user),
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Delete the authenticated user's account.
    
    Rate limited to 3 requests per hour per IP address.
    """
    return await auth_service.delete_account(current_user)


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        first_name=current_user.first_name,
        last_name=current_user.last_name,
        role=current_user.role
    )

