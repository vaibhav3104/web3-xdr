"""
Authentication models for Sentinel3.
"""

from typing import Optional, List
from pydantic import BaseModel, Field
from datetime import datetime


class User(BaseModel):
    """User model."""
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "viewer"  # viewer, operator, admin
    disabled: bool = False
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "email": "admin@web3xdr.io",
                "full_name": "Admin User",
                "role": "admin",
                "disabled": False
            }
        }


class UserInDB(User):
    """User model with hashed password."""
    hashed_password: str


class TokenData(BaseModel):
    """Token payload data."""
    username: Optional[str] = None
    role: Optional[str] = None
    exp: Optional[datetime] = None


class LoginRequest(BaseModel):
    """Login request body."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=4)
    
    class Config:
        json_schema_extra = {
            "example": {
                "username": "admin",
                "password": "your-password"
            }
        }


class LoginResponse(BaseModel):
    """Login response with token."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds
    user: User
    
    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIs...",
                "token_type": "bearer",
                "expires_in": 3600,
                "user": {
                    "username": "admin",
                    "role": "admin"
                }
            }
        }


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    current_password: str
    new_password: str = Field(..., min_length=8)


class CreateUserRequest(BaseModel):
    """Create new user request (admin only)."""
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "viewer"

