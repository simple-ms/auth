from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session
from .database import get_db, init_db
from .models import User
from .schemas import UserCreate, UserLogin, UserResponse, LoginResponse
from .auth import hash_password, verify_password, create_access_token
from .logger import logger

app = FastAPI(
    docs_url="/docs/auth",
    openapi_url="/openapi.json/auth",
    redoc_url="/redoc/auth"
)

security = HTTPBearer()

@app.on_event("startup")
def startup():
    init_db()
    logger.info("User service started")


@app.post(
    "/auth/register", 
    response_model=UserResponse
)
def register(
    user: UserCreate, 
    db: Session = Depends(get_db)
):
    logger.info(f"Registration attempt for username: {user.username}")

    if db.query(User).filter(User.username == user.username).first():
        logger.warning(f"Registration failed: Username '{user.username}' already exists")
        raise HTTPException(status_code=400, detail="User already exists")

    if db.query(User).filter(User.email == user.email).first():
        logger.warning(f"Registration failed: Email '{user.email}' already registered")
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username=user.username,
        email=user.email,
        password=hash_password(user.password)
    )
    logger.info(f"User registered successfully: {user.username}")
    db.add(new_user)
    db.commit()
    return new_user


@app.post("/auth/login", response_model=LoginResponse)
def login(
    user: UserLogin, 
    db: Session = Depends(get_db),
    token: HTTPBearer = Depends(security)
):
    logger.info(f"Login attempt for username: {user.username}")

    db_user = (
        db.query(User).filter(User.username == user.username).first()
    )
    if not db_user or not verify_password(user.password, db_user.password):
        logger.warning(f"Login failed: Invalid credentials for username '{user.username}'")
        raise HTTPException(status_code=400, detail="Invalid credentials")

    access_token = create_access_token(
        data={
            "sub": db_user.username,
            "user_id": str(db_user.id),
            "email": db_user.email,
        }
    )
    logger.info(f"Login successful for user: {user.username} (ID: {db_user.id})")
    return LoginResponse(
        access_token=access_token,
        user_id=db_user.id,
        username=db_user.username
    )



