import uuid
from pydantic import BaseModel, EmailStr, Field
from datetime import datetime
from typing import Optional
from src.users.models import UserRole

class Token(BaseModel):
    """Базовая схема токена"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    """Данные в payload токена"""
    user_id: str
    exp: datetime

class UserLogin(BaseModel):
    """Схема для входа"""
    username: str  # Может быть email или username
    password: str = Field(..., min_length=8)

class UserRegister(BaseModel):
    """Схема для регистрации"""
    username: str = Field(..., min_length=3, max_length=50)
    # email: EmailStr
    password: str = Field(..., min_length=8)
    # first_name: Optional[str] = Field(None, max_length=100)
    # last_name: Optional[str] = Field(None, max_length=100)


# (Python 3.10+) first_name: str | None 
class UserResponse(BaseModel):
    """Ответ с данными пользователя"""
    id: uuid.UUID
    username: str
    first_name: str | None
    last_name: str | None
    email: EmailStr | None
    date_joined: datetime
    last_login: datetime | None
    # role: UserRole | None
    
    class Config:
        from_attributes = True
        