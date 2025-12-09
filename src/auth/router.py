import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from src.auth.schemas import Token, UserLogin, UserRegister, UserResponse
from src.auth.service import AuthService
from .dependencies import CurrentUserDep
from src.users.service import UserService
from src.users.schemas import UserCreate
from src.users.models import User
from src.database import get_db
from src.dependencies import limiter

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse, status_code=201)
@limiter.limit("3/minute")
async def register(
    request: Request,
    user_data: UserRegister,
    db: AsyncSession = Depends(get_db),
    background_tasks: BackgroundTasks = BackgroundTasks()
):
    """Регистрация нового пользователя"""
    try:
    # Конвертация UserRegister → UserCreate
        user_create = UserCreate(
            username=user_data.username,
            password=user_data.password,
        )
        
        # Создание пользователя
        user = await UserService.create_user(db, user_create)
        return user
        # Создание токенов
        # access_token, refresh_token = AuthService.create_tokens(user.id)
        
        # Фоновая задача (welcome email)
       # background_tasks.add_task(send_welcome_email, user.email)
        
        # return Token(
        #     access_token=access_token,
        #     refresh_token=refresh_token
        # )
    
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/login", response_model=Token)
@limiter.limit("5/minute")  # Limit to 5 requests per minute
async def login(request: Request,
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """Вход в систему"""
    # Ищем пользователя
    user = await UserService.get_user_by_username(db, login_data.username)
    
    if not user or not AuthService.authenticate_user(user, login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password"
        )
    # ✅ Обновляем при успешном логине
    user.last_login = datetime.datetime.now()
    # print(f"DEBUG - User last login: {user.last_login}")
    await db.commit()
    # Создание токенов
    access_token, refresh_token = AuthService.create_tokens(user.id)
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token
    )

@router.post("/refresh", response_model=Token)
async def refresh_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
):
    """Обновление access токена"""
    user_id = AuthService.decode_token(refresh_token)
    
    if not user_id:
        raise HTTPException(401, detail="Invalid refresh token")
    
    user = await db.get(User, user_id)
    if not user or not user.is_active:
        raise HTTPException(401, detail="User not found or inactive")
    
    # Создаем новую пару токенов
    access_token, new_refresh_token = AuthService.create_tokens(user.id)
    
    return Token(
        access_token=access_token,
        refresh_token=new_refresh_token
    )

@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUserDep
):
    if not current_user:
        raise HTTPException(401, detail="Not authenticated")
    else:
        return current_user
    # """Получить информацию о текущем пользователе"""
    # print(f"\n=== DEBUG Current User ===")
    # print(f"Type: {type(current_user)}")
    # print(f"Class: {current_user.__class__.__name__}")
    # print(f"Module: {current_user.__class__.__module__}")
    # print(f"MRO: {current_user.__class__.__mro__}")
    
    # Проверяем все атрибуты
    # attrs = ['id', 'username']
    # for attr in attrs:
    #     if hasattr(current_user, attr):
    #         val = getattr(current_user, attr)
    #         print(f"{attr}: {val} (type: {type(val).__name__})")
    #     else:
    #         print(f"{attr}: MISSING!")
    
    # # Пробуем конвертировать
    # try:
    #     result = UserResponse.model_validate(current_user)
    #     print(f"\n✓ Validation successful!")
    #     return result
    # except Exception as e:
    #     print(f"\n✗ Validation error: {e}")
    #     print(f"Error type: {type(e)}")
    #     raise HTTPException(status_code=500, detail=str(e))
    
    # return current_user

@router.post("/logout")
async def logout():
    """Выход из системы (клиентская сторона)"""
    return {"message": "Successfully logged out"}

async def send_welcome_email(email: str):
    """Фоновая задача отправки email"""
    # Реализуйте через ваш email сервис
    pass
