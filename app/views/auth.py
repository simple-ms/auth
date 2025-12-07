from typing import Dict
from fastapi import APIRouter, Depends, Response, Request, HTTPException

from ..schemas.auth import UserCreate, UserLogin, TokenResponse, RefreshRequest, LogoutRequest, UserResponse
from ..services import AuthService
from ..dependencies import get_auth_service, get_token_payload, get_current_user, get_refresh_token_repository
from ..repository import RefreshTokenRepository
from ..models import User

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    request: Request,
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user. Returns user info WITHOUT tokens.
    Users must explicitly log in after registration.
    
    Rate limited to 10 requests per minute per IP address to prevent abuse.
    """
    return await auth_service.register(user_data)


@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    login_data: UserLogin,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Authenticate user and return tokens.
    
    Rate limited to 5 requests per minute per IP address to prevent brute force attacks.
    """
    # Extract session metadata
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    return await auth_service.login(
        login_data,
        ip_address=ip_address,
        user_agent=user_agent
    )


@router.post("/refresh")
async def refresh_token(
    request: Request,
    refresh_request: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Takes a Refresh Token, validates it, and returns new tokens.
    The old refresh token is automatically revoked.
    
    Rate limited to 30 requests per minute per IP address.
    """
    # Extract session metadata
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    
    return await auth_service.refresh_tokens(
        refresh_request.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent
    )


@router.post("/logout")
async def logout(
    request: Request,
    logout_request: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Logout user by blacklisting their refresh token.
    After logout, the refresh token cannot be used to generate new tokens.
    """
    return await auth_service.logout(logout_request.refresh_token)


@router.get("/validate")
async def validate(
    response: Response, 
    payload: Dict = Depends(get_token_payload)
):
    """
    Called by Nginx auth_request.
    Returns 200 OK to Nginx, plus X-User-Id headers.
    """
    user_id = str(payload.get("user_id"))
    role = str(payload.get("role"))
    
    # Nginx reads these headers and passes them to Order/Payment services
    response.headers["X-User-Id"] = user_id
    response.headers["X-User-Role"] = role
    
    return {"status": "valid", "user_id": user_id}


# ===========================================
# SESSION MANAGEMENT ENDPOINTS
# ===========================================

@router.get("/sessions")
async def get_active_sessions(
    current_user: User = Depends(get_current_user),
    refresh_token_repo: RefreshTokenRepository = Depends(get_refresh_token_repository),
    payload: Dict = Depends(get_token_payload)
):
    """
    Get all active sessions for the current user.
    Shows device info, IP address, and creation time for each session.
    """
    sessions = await refresh_token_repo.get_active_sessions(current_user.id)
    
    # Get current JTI from the access token's associated refresh token (if available)
    # Note: Access tokens don't have JTI, so we can't mark "current" session accurately
    # This would require tracking which refresh token was used to create this access token
    
    return {
        "sessions": [
            {
                "jti": s.jti,
                "device_info": s.device_info,
                "ip_address": s.ip_address,
                "user_agent": s.user_agent,
                "created_at": s.created_at.isoformat(),
                "expires_at": s.expires_at.isoformat(),
            }
            for s in sessions
        ],
        "total": len(sessions)
    }


@router.delete("/sessions/{jti}")
async def revoke_session(
    jti: str,
    current_user: User = Depends(get_current_user),
    refresh_token_repo: RefreshTokenRepository = Depends(get_refresh_token_repository)
):
    """
    Revoke a specific session by its JTI.
    The user will need to log in again on that device.
    """
    # Verify the session belongs to the current user before revoking
    sessions = await refresh_token_repo.get_active_sessions(current_user.id)
    session_jtis = [s.jti for s in sessions]
    
    if jti not in session_jtis:
        raise HTTPException(
            status_code=404,
            detail="Session not found or does not belong to you"
        )
    
    revoked = await refresh_token_repo.revoke_token(jti)
    
    if revoked:
        return {"message": "Session revoked successfully"}
    else:
        raise HTTPException(status_code=404, detail="Session not found")


@router.delete("/sessions")
async def revoke_all_sessions(
    current_user: User = Depends(get_current_user),
    refresh_token_repo: RefreshTokenRepository = Depends(get_refresh_token_repository),
    payload: Dict = Depends(get_token_payload)
):
    """
    Revoke all sessions for the current user.
    This will log the user out from all devices.
    
    Note: The current access token will remain valid until it expires (3 minutes).
    """
    # Revoke all refresh tokens for this user
    count = await refresh_token_repo.revoke_all_user_tokens(current_user.id)
    
    return {
        "message": f"Revoked {count} session(s). You will need to log in again on all devices.",
        "revoked_count": count
    }

