# scripts/create_admin.py
#!/usr/bin/env python3
import asyncio
import os
import sys
from pathlib import Path
from pydantic import BaseModel, EmailStr, Field, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession
from src.config import settings

# Добавляем путь к проекту
sys.path.append(str(Path(__file__).parent.parent))

from src.database import async_session_factory
from src.users.models import User, UserRole
from src.users.service import UserService
from src.users.validators import password_validator

class AdminCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=150,pattern=r"^[a-z0-9\-]+$", examples=["username"])
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = Field(default=UserRole.ADMIN)
    is_active: bool = Field(default=True)


async def create_admin(db: AsyncSession, data: AdminCreate) -> User:
    """Создание нового пользователя"""
    # Проверка уникальности email
    # if await UserService.is_email_taken(db, data.email):
    #     raise ValueError(f"Email '{data.email}' уже используется")
    
    # Проверка уникальности username
    if await UserService.is_username_taken(db, data.username):
        raise ValueError(f"Username '{data.username}' уже используется")
    
    # Оценка сложности пароля (опционально)
    score, advice = password_validator.get_password_strength(data.password)
    
    print(f"DEBUG ----- Score: {score}, Advice: {advice}")
    if score < 3:  # Если пароль слабее "хорошего"
        raise ValueError(f"Слабый пароль. {advice}")
    
    # Хеширование пароля
    hashed_password = UserService.hash_password(data.password)
    
    # Создание пользователя
    user = User(
        **data.model_dump(exclude={"password"}),
        password=hashed_password
    )
    
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user




async def main():
    """Создание/восстановление админа из .env"""

    ADMIN_NAME = settings.ADMIN_NAME
    ADMIN_PASSWORD = settings.ADMIN_PASSWORD
    
    if not ADMIN_NAME or not ADMIN_PASSWORD:
        print("❌ Ошибка: Установите ADMIN_NAME и ADMIN_PASSWORD в .env файле")
        print("\nПример .env:")
        print("ADMIN_NAME=superadmin")
        print("ADMIN_PASSWORD=your_strong_password_here")
        # print("ADMIN_EMAIL=admin@yourblog.com")
        sys.exit(1)
    
    async with async_session_factory() as db:
        # Проверяем, существует ли уже админ
        existing_user = await UserService.get_user_by_username(db, ADMIN_NAME)
        if existing_user:
            print(f"ℹ️ Администратор '{ADMIN_NAME}' уже существует")
            # Обновляем пароль если нужно
            update = input("Обновить пароль? (y/n): ").lower()
            if update == 'y':
                existing_user.password = UserService.hash_password(ADMIN_PASSWORD)
                await db.commit()
                print(f"✅ Пароль для '{ADMIN_NAME}' обновлен")
            sys.exit(0)
        
        # Создаем нового админа
        try:
            user_data = AdminCreate(
                username=ADMIN_NAME,
                password=ADMIN_PASSWORD,
                # email=ADMIN_EMAIL,
                is_active=True,
                role=UserRole.ADMIN
            )
            
            user = await create_admin(db, user_data)
            print(f"✅ Администратор создан успешно!")
            print(f"   Имя: {user.username}")
            print(f"   Email: {user.email}")
            print(f"   ID: {user.id}")
            print(f"   Роль: {user.role}")
            
        except ValueError as e:
            print(f"❌ Ошибка валидации: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"❌ Неожиданная ошибка: {e}")
            sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

# UPDATE users SET role = 'admin' WHERE username = 'admin';