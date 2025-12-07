# file: src/users/schemas.py
import uuid
from pydantic import BaseModel, EmailStr, Field, ConfigDict, field_validator
from src.users.models import UserRole
from typing import Optional
from datetime import datetime


# -----------------------------
# Base
# -----------------------------
class UserBase(BaseModel):
    username: str = Field(..., max_length=150,pattern=r"^[a-z0-9\-]+$", examples=["username"]) 
    first_name: Optional[str] = Field(None, max_length=150)
    last_name: Optional[str] = Field(None, max_length=150)
    # is_superuser: bool = Field(default=False)
    # is_staff: bool = Field(default=False)
    is_active: bool = Field(default=True)


# -----------------------------
# Create (POST)
# -----------------------------
class UserCreate(BaseModel):
    username: str = Field(..., max_length=150,pattern=r"^[a-z0-9\-]+$", examples=["username"]) 
    password: str = Field(..., max_length=128)
    # email: EmailStr = Field(..., max_length=254)
    # role: Optional[UserRole] = Field(default=UserRole.USER)
    
    # @field_validator('role')
    # def validate_role(cls, v):
    #     # Запрещаем создавать админов через обычный API
    #     if v in [UserRole.ADMIN, UserRole.SUPERADMIN]:
    #         raise ValueError("Cannot create admin users via this endpoint")
    #     return v

# -----------------------------
# Update (PATCH, partial)
# -----------------------------
class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, max_length=150)
    first_name: Optional[str] = Field(None, max_length=150)
    last_name: Optional[str] = Field(None, max_length=150)
    email: Optional[EmailStr] = Field(None, max_length=254)
    is_superuser: Optional[bool] = None
    is_staff: Optional[bool] = None
    is_active: Optional[bool] = None
    password: Optional[str] = Field(None, min_length=8, max_length=128)


# -----------------------------
# Read (GET)
# -----------------------------
class UserRead(UserBase):
    id: uuid.UUID
    last_login: Optional[datetime] = None
    date_joined: datetime    
    model_config = ConfigDict(from_attributes=True)  # Pydantic v2 style
    