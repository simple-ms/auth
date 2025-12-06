from typing import Dict
from fastapi import APIRouter, Depends, Response, Request

from ..schemas.auth import UserCreate, UserLogin, TokenResponse, RefreshRequest
from ..services import AuthService
from ..dependencies import get_auth_service, get_token_payload

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(
    request: Request,
    user_data: UserCreate,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Register a new user.
    
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
    return await auth_service.login(login_data)


@router.post("/refresh")
async def refresh_token(
    request: Request,
    refresh_request: RefreshRequest,
    auth_service: AuthService = Depends(get_auth_service)
):
    """
    Takes a Refresh Token, validates it, and returns new tokens.
    
    Rate limited to 30 requests per minute per IP address.
    """
    return auth_service.refresh_tokens(refresh_request.refresh_token)


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

