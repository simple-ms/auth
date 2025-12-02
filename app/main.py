from typing import Dict
import jwt
from fastapi import FastAPI, HTTPException, Depends, Security, Response, Header, status
from fastapi.security import HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy import select

from .database import get_db
from .models import User
from .schemas import (
    UserCreate,
    UserLogin,
    TokenResponse,
    RefreshRequest,
    PasswordChange,
    UserResponse
)
from .auth import hash_password, verify_password, create_tokens, verify_token
from .logger import logger
from .config import JWT_SECRET_KEY, JWT_ALGORITHM, AUDIENCE, ISSUER

app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization microservice",
    version="1.0.0",
    docs_url="/docs/auth",
    openapi_url="/openapi.json/auth",
    redoc_url="/redoc/auth"
)

security = HTTPBearer()


# --- HEALTH CHECK ---

@app.get("/auth/health", tags=["Health"])
async def health_check():
    """Health check endpoint for monitoring."""
    return {"status": "healthy", "service": "auth-service"}


# --- PUBLIC ENDPOINTS ---

@app.post(
    "/auth/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Authentication"]
)
async def register(user: UserCreate, db: AsyncSession = Depends(get_db)):
    """
    Register a new user account.
    
    Creates a new user with hashed password and returns access/refresh tokens.
    """
    logger.info(f"Registration attempt for email: {user.email}")
    
    try:
        # Check if user already exists
        result = await db.execute(select(User).filter(User.email == user.email))
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            logger.warning(f"Registration failed: Email already exists - {user.email}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Email already registered"
            )
        
        # Create new user
        new_user = User(
            first_name=user.first_name,
            last_name=user.last_name,
            email=user.email,
            password=hash_password(user.password),
            role=user.role
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)
        
        logger.info(f"User registered successfully: {new_user.id} - {user.email}")
        
        # Generate tokens
        access, refresh = create_tokens({
            "sub": new_user.email,
            "user_id": str(new_user.id),
            "role": new_user.role
        })
        
        return {
            "access_token": access,
            "refresh_token": refresh,
            "user_id": new_user.id,
            "role": new_user.role
        }
        
    except IntegrityError as e:
        await db.rollback()
        logger.error(f"Database integrity error during registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered"
        )
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error during registration: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )


@app.post(
    "/auth/login",
    response_model=TokenResponse,
    tags=["Authentication"]
)
async def login(user: UserLogin, db: AsyncSession = Depends(get_db)):
    """
    Login with email and password.
    
    Returns access and refresh tokens upon successful authentication.
    """
    logger.info(f"Login attempt for email: {user.email}")
    
    try:
        # Find user by email
        result = await db.execute(select(User).filter(User.email == user.email))
        db_user = result.scalar_one_or_none()
        
        if not db_user:
            logger.warning(f"Login failed: User not found - {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        # Verify password
        if not verify_password(user.password, db_user.password):
            logger.warning(f"Login failed: Invalid password - {user.email}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        logger.info(f"User logged in successfully: {db_user.id} - {user.email}")
        
        # Generate tokens
        access, refresh = create_tokens({
            "sub": db_user.email,
            "user_id": str(db_user.id),
            "role": db_user.role
        })
        
        return {
            "access_token": access,
            "refresh_token": refresh,
            "user_id": db_user.id,
            "role": db_user.role
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Unexpected error during login: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An error occurred during login"
        )


@app.post("/auth/refresh", tags=["Authentication"])
async def refresh_token(request: RefreshRequest):
    """
    Refresh access token using refresh token.
    
    Returns new access and refresh tokens.
    """
    logger.info("Token refresh attempt")
    
    try:
        # Decode and validate refresh token
        payload = jwt.decode(
            request.refresh_token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            audience=AUDIENCE,
            issuer=ISSUER
        )
        
        # Verify it's a refresh token
        if payload.get("type") != "refresh":
            logger.warning("Token refresh failed: Invalid token type")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        logger.info(f"Token refreshed for user: {payload.get('user_id')}")
        
        # Generate new tokens
        new_access, new_refresh = create_tokens({
            "sub": payload["sub"],
            "user_id": payload["user_id"],
            "role": payload["role"]
        })
        
        return {
            "access_token": new_access,
            "refresh_token": new_refresh
        }
        
    except jwt.ExpiredSignatureError:
        logger.warning("Token refresh failed: Refresh token expired")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has expired"
        )
    except jwt.InvalidTokenError as e:
        logger.warning(f"Token refresh failed: Invalid token - {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


# --- INTERNAL/PROTECTED ENDPOINTS ---

@app.get("/auth/validate", tags=["Internal"])
async def validate(response: Response, payload: Dict = Security(verify_token)):
    """
    Validate access token (used by API Gateway).
    
    This endpoint is called by Nginx to validate tokens and extract user info.
    Returns user_id and role in response headers.
    """
    user_id = str(payload.get("user_id"))
    user_role = str(payload.get("role"))
    
    logger.debug(f"Token validated for user: {user_id}")
    
    # Set headers for Nginx to forward to downstream services
    response.headers["X-User-Id"] = user_id
    response.headers["X-User-Role"] = user_role
    
    return {"status": "valid", "user_id": user_id, "role": user_role}


@app.put("/auth/password", tags=["User Management"])
async def change_password(
    password_data: PasswordChange,
    db: AsyncSession = Depends(get_db),
    x_user_id: str = Header(None, alias="X-User-Id"),
    token: str = Depends(security)  # Shows lock icon in Swagger
):
    """
    Change user password.
    
    Requires current password for verification.
    User ID is extracted from X-User-Id header (set by Nginx after token validation).
    """
    if not x_user_id:
        logger.warning("Password change failed: Missing X-User-Id header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )
    
    logger.info(f"Password change attempt for user: {x_user_id}")
    
    try:
        # Find user
        result = await db.execute(select(User).filter(User.id == x_user_id))
        db_user = result.scalar_one_or_none()
        
        if not db_user:
            logger.warning(f"Password change failed: User not found - {x_user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Verify old password
        if not verify_password(password_data.old_password, db_user.password):
            logger.warning(f"Password change failed: Invalid old password - {x_user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is incorrect"
            )
        
        # Update password
        db_user.password = hash_password(password_data.new_password)
        await db.commit()
        
        logger.info(f"Password changed successfully for user: {x_user_id}")
        return {"message": "Password changed successfully"}
        
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error during password change: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )


@app.delete("/auth/me", status_code=status.HTTP_200_OK, tags=["User Management"])
async def delete_account(
    db: AsyncSession = Depends(get_db),
    x_user_id: str = Header(None, alias="X-User-Id"),
    token: str = Depends(security)
):
    """
    Delete user account.
    
    Removes authentication credentials from the database.
    Note: This doesn't delete user profile data in other services (would require Kafka event).
    """
    if not x_user_id:
        logger.warning("Account deletion failed: Missing X-User-Id header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized"
        )
    
    logger.info(f"Account deletion attempt for user: {x_user_id}")
    
    try:
        # Find user
        result = await db.execute(select(User).filter(User.id == x_user_id))
        db_user = result.scalar_one_or_none()
        
        if not db_user:
            logger.warning(f"Account deletion failed: User not found - {x_user_id}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Delete user
        await db.delete(db_user)
        await db.commit()
        
        logger.info(f"Account deleted successfully: {x_user_id}")
        
        # TODO: Publish user_deleted event to Kafka for other services to clean up
        
        return {"message": "Account deleted successfully"}
        
    except HTTPException:
        raise
    except SQLAlchemyError as e:
        await db.rollback()
        logger.error(f"Database error during account deletion: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Database error occurred"
        )