from typing import Dict
from fastapi import FastAPI, HTTPException, Depends, Security, Response, status, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from .database import get_db
from .models import User
from .schemas import (
    UserCreate, UserLogin, TokenResponse, 
    RefreshRequest, PasswordChange
)
from .auth import (
    hash_password, verify_password, create_tokens, 
    verify_access_token, verify_refresh_token
)
from .logger import logger

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

# NOTE: CORS is handled by nginx gateway - no CORS middleware here

security = HTTPBearer()


async def get_token_payload(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> Dict:
    """
    Extracts token and ensures it is a valid ACCESS token.
    Used for lightweight validation (like Nginx checks).
    """
    token = credentials.credentials
    return verify_access_token(token)

async def get_current_user(
    payload: Dict = Depends(get_token_payload),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Validates Access Token AND ensures user exists in DB.
    Used for /me, /password, etc.
    """
    user_id = payload.get("user_id")
    result = await db.execute(select(User).filter(User.id == user_id))
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


# --- PUBLIC ENDPOINTS ---

@app.get("/auth/health", tags=["Health"])
async def health_check(db: AsyncSession = Depends(get_db)):
    """Health check endpoint with database connectivity check."""
    try:
        await db.execute(select(1))
        return {
            "status": "healthy",
            "service": "auth-service",
            "database": "connected"
        }
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "unhealthy",
                "service": "auth-service",
                "database": "disconnected"
            }
        )

@app.post("/auth/register", response_model=TokenResponse, status_code=201)
@limiter.limit("10/minute")  # Rate limit: 10 registrations per minute per IP
async def register(
    request: Request,
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Register a new user.
    
    Rate limited to 10 requests per minute per IP address to prevent abuse.
    """
    logger.info(f"Registration attempt: {user_data.email}")
    try:
        new_user = User(
            first_name=user_data.first_name,
            last_name=user_data.last_name,
            email=user_data.email,
            password=hash_password(user_data.password),
            role=user_data.role
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        # Auto-login: Create tokens immediately
        access, refresh = create_tokens({
            "sub": new_user.email,
            "user_id": str(new_user.id),
            "role": new_user.role
        })
        return {
            "access_token": access, "refresh_token": refresh,
            "user_id": new_user.id, "role": new_user.role
        }
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Email already registered")
    except Exception as e:
        await db.rollback()
        logger.error(f"Reg Error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")

@app.post("/auth/login", response_model=TokenResponse)
@limiter.limit("5/minute")  # Rate limit: 5 login attempts per minute per IP
async def login(
    request: Request,
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Authenticate user and return tokens.
    
    Rate limited to 5 requests per minute per IP address to prevent brute force attacks.
    """
    logger.info(f"Login attempt for email: {login_data.email}")
    result = await db.execute(select(User).filter(User.email == login_data.email))
    user = result.scalar_one_or_none()
    
    if not user:
        logger.warning(f"User not found: {login_data.email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    logger.info(f"User found: {user.email}, verifying password...")
    password_valid = verify_password(login_data.password, user.password)
    logger.info(f"Password verification result: {password_valid}")
    
    if not password_valid:
        logger.warning(f"Invalid password for user: {login_data.email}")
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access, refresh = create_tokens({
        "sub": user.email,
        "user_id": str(user.id),
        "role": user.role
    })
    return {
        "access_token": access, "refresh_token": refresh,
        "user_id": user.id, "role": user.role
    }

@app.post("/auth/refresh")
@limiter.limit("30/minute")  # Rate limit: 30 refresh requests per minute
async def refresh_token(request: Request, refresh_request: RefreshRequest):
    """
    Takes a Refresh Token, validates it, and returns new tokens.
    
    Rate limited to 30 requests per minute per IP address.
    """
    # STRICT CHECK: Will raise 401 if token is not type='refresh'
    payload = verify_refresh_token(refresh_request.refresh_token)
    
    new_access, new_refresh = create_tokens({
        "sub": payload["sub"],
        "user_id": payload["user_id"],
        "role": payload["role"]
    })
    return {"access_token": new_access, "refresh_token": new_refresh}


# --- INTERNAL ENDPOINT (For Nginx) ---

@app.get("/auth/validate")
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


# --- PROTECTED ENDPOINTS (For Users) ---

@app.put("/auth/password")
@limiter.limit("3/minute")  # Rate limit: 3 password change attempts per minute
async def change_password(
    request: Request,
    password_data: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Change password for authenticated user.
    
    Rate limited to 3 requests per minute per IP address.
    """
    if not verify_password(password_data.old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    
    current_user.password = hash_password(password_data.new_password)
    await db.commit()
    
    return {"message": "Password changed successfully"}

@app.delete("/auth/me")
@limiter.limit("3/hour")  # Rate limit: 3 account deletions per hour (very restrictive)
async def delete_account(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Delete the authenticated user's account.
    
    Rate limited to 3 requests per hour per IP address.
    """
    await db.delete(current_user)
    await db.commit()
    return {"message": "Account deleted successfully"}

@app.get("/auth/me")
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """Get current user information."""
    return {
        "id": current_user.id,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "role": current_user.role
    }
