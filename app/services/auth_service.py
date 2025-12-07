from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple, Optional
import uuid

from passlib.hash import argon2
import jwt
from fastapi import HTTPException, status
from sqlalchemy.exc import IntegrityError

from ..settings import settings
from ..models.user import User
from ..repository import UserRepository, RefreshTokenRepository
from ..schemas.auth import UserCreate, UserLogin, TokenResponse
from ..logger import logger


class AuthService:
    """Service for authentication business logic."""
    
    def __init__(
        self,
        user_repository: UserRepository,
        refresh_token_repository: Optional[RefreshTokenRepository] = None
    ):
        self.user_repository = user_repository
        self.refresh_token_repository = refresh_token_repository
    
    # --- Password Operations ---
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using Argon2."""
        return argon2.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify a password against its hash."""
        try:
            return argon2.verify(plain_password, hashed_password)
        except Exception:
            return False
    
    # --- Token Operations ---
    
    @staticmethod
    def create_tokens(data: Dict[str, str]) -> Tuple[str, str]:
        """Create Access and Refresh tokens with distinct types."""
        now = datetime.now(timezone.utc)
        
        base_payload = {
            "iss": settings.ISSUER,
            "aud": settings.AUDIENCE,
            "iat": now,
        }
        
        # Create Access Token
        access_payload = base_payload.copy()
        access_payload.update(data)
        access_payload.update({
            "exp": now + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES),
            "type": "access"
        })
        access_token = jwt.encode(access_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        # Create Refresh Token
        refresh_payload = base_payload.copy()
        refresh_payload.update(data)
        refresh_payload.update({
            "exp": now + timedelta(days=settings.JWT_REFRESH_EXPIRATION_DAYS),
            "type": "refresh",
            "jti": str(uuid.uuid4())
        })
        refresh_token = jwt.encode(refresh_payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

        return access_token, refresh_token
    
    @staticmethod
    def _decode_jwt(token: str) -> Dict:
        """Internal Helper: Decode and validate JWT signature."""
        try:
            return jwt.decode(
                token,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                audience=settings.AUDIENCE,
                issuer=settings.ISSUER
            )
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Token has expired"
            )
        except jwt.InvalidTokenError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token"
            )
    
    @staticmethod
    def verify_access_token(token: str) -> Dict:
        """STRICTLY verify that the token is an ACCESS token."""
        payload = AuthService._decode_jwt(token)
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token type: Access token required"
            )
        return payload
    
    async def verify_refresh_token(self, token: str) -> Dict:
        """STRICTLY verify that the token is a REFRESH token and is active."""
        payload = self._decode_jwt(token)
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, 
                detail="Invalid token type: Refresh token required"
            )
        
        # Check if token is active (exists and not revoked)
        if self.refresh_token_repository:
            jti = payload.get("jti")
            if jti and not await self.refresh_token_repository.is_token_valid(jti):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Token has been revoked or does not exist"
                )
        
        return payload
    
    # --- User Operations ---
    
    async def register(self, user_data: UserCreate) -> Dict:
        """Register a new user. Returns user info WITHOUT tokens."""
        logger.info(f"Registration attempt: {user_data.email}")
        
        try:
            new_user = User(
                first_name=user_data.first_name,
                last_name=user_data.last_name,
                email=user_data.email,
                password=self.hash_password(user_data.password),
                role=user_data.role
            )
            await self.user_repository.create(new_user)
            
            logger.info(f"User registered successfully: {new_user.email}")
            
            # Return user info only - no tokens
            return {
                "message": "Registration successful. Please log in.",
                "user_id": str(new_user.id),
                "email": new_user.email,
                "role": new_user.role
            }
        except IntegrityError:
            await self.user_repository.rollback()
            raise HTTPException(status_code=409, detail="Email already registered")
        except Exception as e:
            await self.user_repository.rollback()
            logger.error(f"Registration Error: {e}")
            raise HTTPException(status_code=500, detail="Internal Server Error")
    
    async def login(
        self,
        login_data: UserLogin,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> TokenResponse:
        """Authenticate user and return tokens."""
        logger.info(f"Login attempt for email: {login_data.email}")
        
        user = await self.user_repository.get_by_email(login_data.email)
        
        if not user:
            logger.warning(f"User not found: {login_data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not self.verify_password(login_data.password, user.password):
            logger.warning(f"Invalid password for user: {login_data.email}")
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        # Update last login timestamp
        user.last_login = datetime.now(timezone.utc)
        await self.user_repository.update(user)
        
        # Create tokens
        access, refresh = self.create_tokens({
            "sub": user.email,
            "user_id": str(user.id),
            "role": user.role
        })
        
        # Store refresh token in database with session metadata
        if self.refresh_token_repository:
            # Decode without validation to extract JTI (token already created by us)
            refresh_payload = jwt.decode(
                refresh,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_signature": False, "verify_aud": False, "verify_iss": False}
            )
            jti = refresh_payload.get("jti")
            exp = refresh_payload.get("exp")
            if jti and exp:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                await self.refresh_token_repository.create_token(
                    jti=jti,
                    user_id=user.id,
                    expires_at=expires_at,
                    device_info=device_info,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        
        logger.info(f"User logged in successfully: {user.email}")
        
        return TokenResponse(
            access_token=access,
            refresh_token=refresh,
            user_id=user.id,
            role=user.role
        )
    
    async def refresh_tokens(
        self,
        refresh_token: str,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, str]:
        """Refresh tokens using a valid refresh token. Revokes the old token."""
        payload = await self.verify_refresh_token(refresh_token)
        
        # Revoke the old refresh token
        if self.refresh_token_repository:
            old_jti = payload.get("jti")
            if old_jti:
                await self.refresh_token_repository.revoke_token(old_jti)
                logger.info(f"Revoked old refresh token: {old_jti}")
        
        # Create new tokens
        new_access, new_refresh = self.create_tokens({
            "sub": payload["sub"],
            "user_id": payload["user_id"],
            "role": payload["role"]
        })
        
        # Store new refresh token in database
        if self.refresh_token_repository:
            # Decode without validation to extract JTI (token already created by us)
            refresh_payload = jwt.decode(
                new_refresh,
                settings.JWT_SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_signature": False, "verify_aud": False, "verify_iss": False}
            )
            new_jti = refresh_payload.get("jti")
            exp = refresh_payload.get("exp")
            user_id = payload.get("user_id")
            if new_jti and exp and user_id:
                expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
                await self.refresh_token_repository.create_token(
                    jti=new_jti,
                    user_id=uuid.UUID(user_id),
                    expires_at=expires_at,
                    device_info=device_info,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        
        return {"access_token": new_access, "refresh_token": new_refresh}
    
    async def logout(self, refresh_token: str) -> Dict[str, str]:
        """Logout user by revoking their refresh token."""
        try:
            payload = await self.verify_refresh_token(refresh_token)
            
            # Revoke the refresh token
            if self.refresh_token_repository:
                jti = payload.get("jti")
                if jti:
                    await self.refresh_token_repository.revoke_token(jti)
                    logger.info(f"User logged out, token revoked: {jti}")
            
            return {"message": "Logged out successfully"}
        except HTTPException:
            # Even if token is invalid, return success for logout
            return {"message": "Logged out successfully"}
    
    async def change_password(self, user: User, old_password: str, new_password: str) -> Dict[str, str]:
        """Change user password and revoke all refresh tokens."""
        if not self.verify_password(old_password, user.password):
            raise HTTPException(status_code=400, detail="Old password incorrect")
        
        # Update password
        user.password = self.hash_password(new_password)
        await self.user_repository.update(user)
        
        # Revoke ALL refresh tokens - force re-login on all devices
        if self.refresh_token_repository:
            revoked_count = await self.refresh_token_repository.revoke_all_user_tokens(user.id)
            logger.info(f"Password changed for user: {user.email}, revoked {revoked_count} refresh tokens")
        else:
            logger.info(f"Password changed for user: {user.email}")
        
        return {
            "message": "Password changed successfully. Please log in again on all devices."
        }
    
    async def delete_account(self, user: User) -> Dict[str, str]:
        """Delete user account."""
        await self.user_repository.delete(user)
        logger.info(f"Account deleted: {user.email}")
        return {"message": "Account deleted successfully"}
    
    async def get_current_user(self, user_id: str) -> User:
        """Get current user by ID from token payload."""
        user = await self.user_repository.get_by_id(user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user

