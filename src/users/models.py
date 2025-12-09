import enum
from sqlalchemy import Enum, String, Boolean, DateTime
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func
# from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime
from typing import List, Optional
from src.database import Base
# from src.auth.password_validator import PasswordValidator
import uuid

class UserRole(enum.Enum):
    """Роли с соответствующими пермишенами"""
    SUPERADMIN = "superadmin"  # Все права
    ADMIN = "admin"           # Админ без sensitive операций
    EDITOR = "editor"         # Редактирование контента
    AUTHOR = "author"         # Создание своего контента
    USER = "user"            # Базовые права
    GUEST = "guest"          # Только чтение
    
    # Методы для проверки прав
    @property
    def permissions(self) -> List[str]:
        permissions_map = {
            UserRole.SUPERADMIN: ["*"],
            UserRole.ADMIN: ["manage_users", "manage_content", "view_reports"],
            UserRole.EDITOR: ["create_content", "edit_content", "publish_content"],
            UserRole.AUTHOR: ["create_content", "edit_own_content"],
            UserRole.USER: ["view_content", "comment"],
            UserRole.GUEST: ["view_content"]
        }
        return permissions_map.get(self, [])
    
    def has_permission(self, permission: str) -> bool:
        if self.permissions == ["*"]:
            return True
        return permission in self.permissions

class User(Base):
    __tablename__ = "users"
    
    # Primary key - автоинкремент по умолчанию в SQLAlchemy
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4) 
    password: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    # User fields
    username: Mapped[str] = mapped_column(
        String(150), 
        nullable=False, 
        unique=True,  # ← Добавить unique constraint
        index=True    # ← Добавить индекс для быстрого поиска
    )
    email: Mapped[str] = mapped_column(
        String(254), 
        nullable=True, 
        unique=True,  # ← Email тоже должен быть уникальным
        # index=True
    )
    first_name: Mapped[str] = mapped_column(String(150), default="", nullable=True)
    last_name: Mapped[str] = mapped_column(String(150), default="", nullable=True)
 
    # Timestamps
    date_joined: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),  # ← server_default
        nullable=False
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True),
        nullable=True
    )
    
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="user_role"),
        default=UserRole.USER,
        nullable=False
    )


    #token_version: Mapped[int] = mapped_column(Integer, default=1)  # ← Ключевое поле!
    

    # def increment_token_version(self):
    #     """Увеличить версию токена (при смене пароля/принудительном logout)"""
    #     self.token_version += 1
    #     if self.token_version > 100:
    #         self.token_version = 1
        # self.updated_at = datetime.now(timezone.utc)

    # Методы для работы с паролями
    # def set_password(self, password: str):
    #     """Установка пароля с хешированием"""
    #     self.password = PasswordValidator.hash(password)
    
    # def check_password(self, password: str) -> bool:
    #     """Проверка пароля"""
    #     return PasswordValidator.verify(password, self.password)
    
    # def needs_password_rehash(self) -> bool:
    #     """Нужно ли перехешировать пароль"""
    #     return PasswordValidator.needs_rehash(self.password)