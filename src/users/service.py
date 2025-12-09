# file: src/users/service.py (обновленная часть)
import uuid
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from src.users.models import User, UserRole
from src.users.schemas import UserCreate
from src.users.validators import password_validator


# file: src/auth/service.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Optional

from src.users.models import User




class UserService:
    """Сервис для работы с пользователями"""
    
    @staticmethod
    async def is_email_taken(db: AsyncSession, email: str) -> bool:
        """Проверка, занят ли email"""
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    @staticmethod
    async def is_username_taken(db: AsyncSession, username: str) -> bool:
        """Проверка, занят ли username"""
        stmt = select(User).where(User.username == username)
        result = await db.execute(stmt)
        return result.scalar_one_or_none() is not None

    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширование пароля с использованием Argon2"""
        return password_validator.hash_password(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Верификация пароля"""
        return password_validator.verify_password(plain_password, hashed_password)
    
    

    @staticmethod
    async def create_user(db: AsyncSession, data: UserCreate) -> User:
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
        # print("************************************************8")
        # print(f"DEBUG: Created user: {user.id}, {user.username}")
        return user

    @staticmethod
    async def get_user_by_id(db: AsyncSession, id: uuid.UUID) -> Optional[User]:
        """Получение пользователя по ID"""
        return await db.get(User, id)

    @staticmethod
    async def get_user_by_email(db: AsyncSession, email: str) -> Optional[User]:
        """Получение пользователя по email"""
        stmt = select(User).where(User.email == email)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def get_user_by_username(db: AsyncSession, username: str) -> Optional[User]:
        """Получение пользователя по username"""
        stmt = select(User).where(User.username == username)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    # @staticmethod
    # async def authenticate_user(
    #     db: AsyncSession, 
    #     identifier: str,  # username или email
    #     password: str
    # ) -> Optional[User]:
    #     """Аутентификация пользователя"""
    #     # Ищем по username или email
    #     stmt = select(User).where(
    #         (User.username == identifier) | (User.email == identifier)
    #     )
    #     result = await db.execute(stmt)
    #     user = result.scalar_one_or_none()
        
    #     if not user or not user.check_password(password):
    #         return None
        
    #     # Если параметры хеширования устарели, перехешируем
    #     if user.needs_password_rehash():
    #         user.set_password(password)
    #         await db.commit()
        
    #     return user

    @staticmethod
    async def get_users_list(db: AsyncSession, skip: int = 0, limit: int = 100) -> list[User]:
        """Получение списка пользователей с пагинацией"""
        stmt = select(User).offset(skip).limit(limit)
        result = await db.execute(stmt)
        return list(result.scalars().all())
    
    @staticmethod
    async def can_edit_content(user: User, content_owner_id: int) -> bool:
        """Может ли пользователь редактировать контент"""
        if user.role in [UserRole.ADMIN, UserRole.EDITOR]:
            return True
        if user.role == UserRole.AUTHOR and user.id == content_owner_id:
            return True
        return False
    
    @staticmethod
    async def promote_to_publisher(db: AsyncSession, user_id: int) -> User:
        """Повышение роли пользователя"""
        user = await db.get(User, user_id)
        if not user:
            raise ValueError("User not found")
        
        # Бизнес-логика повышения
        if user.role == UserRole.USER:
            user.role = UserRole.AUTHOR
            await db.commit()
        
        return user
    


   # user =UserService.create_user