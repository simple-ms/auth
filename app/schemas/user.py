from uuid import UUID
from pydantic import BaseModel


class UserResponse(BaseModel):
    """Schema for user profile response."""
    id: UUID
    email: str
    first_name: str
    last_name: str
    role: str
    
    class Config:
        from_attributes = True

