from datetime import datetime, timezone
from typing import List, Optional
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, delete, update

from ..models.refresh_token import RefreshToken


class RefreshTokenRepository:
    """Repository for managing active refresh tokens and sessions."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def create_token(
        self,
        jti: str,
        user_id: uuid.UUID,
        expires_at: datetime,
        device_info: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> RefreshToken:
        """Create a new active refresh token."""
        token = RefreshToken(
            jti=jti,
            user_id=user_id,
            expires_at=expires_at,
            device_info=device_info,
            ip_address=ip_address,
            user_agent=user_agent
        )
        self.db.add(token)
        await self.db.commit()
        await self.db.refresh(token)
        return token
    
    async def is_token_valid(self, jti: str) -> bool:
        """Check if a token exists and is not revoked."""
        result = await self.db.execute(
            select(RefreshToken).filter(
                RefreshToken.jti == jti,
                RefreshToken.revoked == False
            )
        )
        return result.scalar_one_or_none() is not None
    
    async def revoke_token(self, jti: str) -> bool:
        """Revoke a specific token. Returns True if token was found and revoked."""
        result = await self.db.execute(
            update(RefreshToken)
            .filter(RefreshToken.jti == jti)
            .values(revoked=True, revoked_at=datetime.now(timezone.utc))
        )
        await self.db.commit()
        return result.rowcount > 0
    
    async def get_active_sessions(self, user_id: uuid.UUID) -> List[RefreshToken]:
        """Get all active (non-revoked, non-expired) sessions for a user."""
        now = datetime.now(timezone.utc)
        result = await self.db.execute(
            select(RefreshToken).filter(
                RefreshToken.user_id == user_id,
                RefreshToken.revoked == False,
                RefreshToken.expires_at > now
            ).order_by(RefreshToken.created_at.desc())
        )
        return list(result.scalars().all())
    
    async def revoke_all_user_tokens(self, user_id: uuid.UUID, except_jti: Optional[str] = None) -> int:
        """
        Revoke all tokens for a user, optionally excluding one token.
        Returns the number of tokens revoked.
        """
        query = update(RefreshToken).filter(
            RefreshToken.user_id == user_id,
            RefreshToken.revoked == False
        )
        
        if except_jti:
            query = query.filter(RefreshToken.jti != except_jti)
        
        query = query.values(revoked=True, revoked_at=datetime.now(timezone.utc))
        
        result = await self.db.execute(query)
        await self.db.commit()
        return result.rowcount
    
    async def cleanup_expired(self, before: datetime = None) -> int:
        """
        Remove expired tokens from the database.
        
        Args:
            before: Remove tokens that expired before this time.
                   Defaults to current time.
        
        Returns:
            Number of tokens removed.
        """
        if before is None:
            before = datetime.now(timezone.utc)
        
        result = await self.db.execute(
            delete(RefreshToken).filter(RefreshToken.expires_at < before)
        )
        await self.db.commit()
        return result.rowcount
    
    async def rollback(self) -> None:
        """Rollback the current transaction."""
        await self.db.rollback()
