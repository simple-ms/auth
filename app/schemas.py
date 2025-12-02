from uuid import UUID
from pydantic import BaseModel, EmailStr
from typing import Literal

class UserCreate(BaseModel):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    role: Literal["buyer", "seller"] = "buyer"

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class PasswordChange(BaseModel):
    old_password: str
    new_password: str

class RefreshRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: UUID
    role: str

class UserResponse(BaseModel):
    id: UUID
    username: str # Constructed from First/Last name usually, or just use email
    email: str
    role: str
    
    class Config:
        from_attributes = True