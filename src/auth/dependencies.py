import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Annotated, Optional

from src.auth.service import AuthService
from src.users.models import User, UserRole
from src.database import get_db

security = HTTPBearer(auto_error=False)

# 1. Основная зависимость для получения пользователя
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Получение текущего пользователя из токена"""
    if not credentials:
        # print("**** DEBUG: credentials is None")
        return None

    try:
        # 1. verify_token возвращает (claims, error)
        claims, error = AuthService.verify_token(credentials.credentials)
        
        # 2. Проверяем ошибку
        if error:
            # Логируем ошибку если нужно
            # print(f"Token verification failed: {error}")
            return None
        
        # 3. Проверяем claims
        if not claims:
            return None
        
        # 4. Извлекаем user_id
        user_id_str = claims.get("sub")
        if not user_id_str:
            return None
        
        # 5. Проверяем тип токена (только access token)
        if claims.get("type") != "access":
            return None
        
        # 6. Конвертируем в UUID
        try:
            user_id = uuid.UUID(user_id_str)
        except ValueError:
            return None
        
        # 7. Получаем пользователя
        user = await db.get(User, user_id)
        if not user or not user.is_active:
            return None
        
        return user
        
    except Exception:
        # Любая ошибка - возвращаем None
        return None


async def require_auth(
    current_user: Optional[User] = Depends(get_current_user)
) -> User:
    """Требует авторизацию"""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return current_user

# 2. Фабрика для проверки ролей
def require_role(required_role: UserRole):
    async def role_checker(
        current_user: User = Depends(require_auth)
    ) -> User:
        if current_user.role != required_role:
            raise HTTPException(403, detail=f"Role {required_role.value} required")
        return current_user
    return Depends(role_checker)


# async def require_admin(
#     current_user: User = Depends(require_auth)
# ) -> User:
#     """Требует права администратора"""
#     if not current_user.is_superuser:
#         raise HTTPException(
#             status_code=status.HTTP_403_FORBIDDEN,
#             detail="Admin privileges required"
#         )
#     return current_user

# 3. Определяем зависимости
CurrentUserDep = Annotated[User, Depends(get_current_user)]
CurrentAdminDep = Annotated[User, require_role(UserRole.ADMIN)] 
OptionalUserDep = Annotated[Optional[User], Depends(get_current_user)]
