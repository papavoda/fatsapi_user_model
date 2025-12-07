# file: src/users/router.py
import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated

from src.users.models import UserRole
from src.users.schemas import UserCreate, UserRead
from src.users.service import UserService
from src.database import get_db
from src.auth.dependencies  import require_role


# Типизированная зависимость для БД
DatabaseDep = Annotated[AsyncSession, Depends(get_db)]


# Для админов
admin_router = APIRouter(
    prefix="/users",
    tags=["Users (Admin)"],
    dependencies=[require_role(UserRole.ADMIN)]
)

#-----------------------------------------------------------
# Create user
#-----------------------------------------------------------
@admin_router.post(
    "/post",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
    summary="Создать нового пользователя",
    responses={
        201: {"description": "Пользователь успешно создан"},
        400: {"description": "Невалидные данные или пользователь уже существует"},
        500: {"description": "Внутренняя ошибка сервера"}
    }
)
async def create_user(
    user_data: UserCreate,
    db: DatabaseDep,

) :

    try:
        # Создаем пользователя через сервис
        user = await UserService.create_user(db, user_data)
        user = UserRead.model_validate(user)
        return user
 
        
    except ValueError as e:
        # Обработка бизнес-ошибок (дубликаты email/username)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    

# По ID
@admin_router.get(
    "/{user_id}",
    response_model=UserRead,
    summary="Получить пользователя по ID",
    responses={
        200: {"description": "Пользователь найден"},
        404: {"description": "Пользователь не найден"}
    }
)
async def get_user_by_id(
    id: uuid.UUID,
    db: DatabaseDep
) -> UserRead:
    """Получить информацию о пользователе по его ID"""
    user = await UserService.get_user_by_id(db, id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User with ID {id} not found"
        )
    return UserRead.model_validate(user)

@admin_router.get(
    "/",
    response_model=list[UserRead],
    summary="Получить список всех пользователей",
    description="Возвращает список всех активных пользователей системы"
)
async def get_users_list(
    db: DatabaseDep,
) -> list:
    """Получить список пользователей с пагинацией"""
    users = await UserService.get_users_list(db)
    return list(users)




# users_router = APIRouter(prefix="/users", tags=["Users"])




# -----------------------------------------------------------
# Дополнительные эндпоинты (опционально)
# -----------------------------------------------------------


    """
    Создание нового пользователя в системе.
    
    - **username**: Уникальное имя пользователя (3-150 символов)
    - **email**: Уникальный email адрес
    - **password**: Пароль (минимум 8 символов)
    - **first_name**: Имя пользователя
    - **last_name**: Фамилия пользователя
    - **is_active**: Активен ли пользователь (по умолчанию True)
    Возвращает созданного пользователя без поля password.
    """