from typing import Dict
from fastapi import FastAPI, HTTPException, Depends, Security, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import IntegrityError
from sqlalchemy import select

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

app = FastAPI(
    title="Auth Service",
    description="Authentication and authorization microservice",
    version="1.0.0",
    docs_url="/docs/auth",
    openapi_url="/openapi.json/auth",
    redoc_url="/redoc/auth"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8080", "http://127.0.0.1:8080"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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
async def health_check():
    return {"status": "healthy", "service": "auth-service"}

@app.post("/auth/register", response_model=TokenResponse, status_code=201)
async def register(user_data: UserCreate, db: AsyncSession = Depends(get_db)):
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
async def login(login_data: UserLogin, db: AsyncSession = Depends(get_db)):
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
async def refresh_token(request: RefreshRequest):
    """
    Takes a Refresh Token, validates it, and returns new tokens.
    """
    # STRICT CHECK: Will raise 401 if token is not type='refresh'
    payload = verify_refresh_token(request.refresh_token)
    
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
    payload: Dict = Depends(get_token_payload) # Validates Access Token
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
async def change_password(
    password_data: PasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    if not verify_password(password_data.old_password, current_user.password):
        raise HTTPException(status_code=400, detail="Old password incorrect")
    
    current_user.password = hash_password(password_data.new_password)
    await db.commit()
    
    return {"message": "Password changed successfully"}

@app.delete("/auth/me")
async def delete_account(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    await db.delete(current_user)
    await db.commit()
    return {"message": "Account deleted successfully"}