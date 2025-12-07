from datetime import datetime, timezone
from typing import Optional
import uuid
from sqlalchemy import String, DateTime, Boolean, ForeignKey, Index
from sqlalchemy.orm import Mapped, mapped_column
from ..database import Base


class RefreshToken(Base):
    """Active refresh token storage for session management."""
    
    __tablename__ = "refresh_tokens"

    # JWT ID (jti claim) - unique identifier for the refresh token
    jti: Mapped[str] = mapped_column(String(255), primary_key=True)
    
    # User who owns this token
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), index=True)
    
    # Token lifecycle timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc)
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True
    )
    
    # Session/device information for security and UX
    device_info: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)  # IPv6 max length
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    
    # Revocation tracking
    revoked: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    # Indexes for efficient queries
    __table_args__ = (
        Index('idx_refresh_token_user_active', 'user_id', 'revoked'),
        Index('idx_refresh_token_expires', 'expires_at'),
    )
    
    def __repr__(self) -> str:
        return f"<RefreshToken(jti={self.jti}, user_id={self.user_id}, revoked={self.revoked})>"
