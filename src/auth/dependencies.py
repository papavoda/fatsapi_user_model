from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import ExpiredSignatureError, JWTError
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
        user_id = AuthService.decode_token(credentials.credentials)
    except ExpiredSignatureError:
        raise HTTPException(401, detail="Token expired")
    except JWTError:
        return None
    
    # print("DEBUG: user_id:", user_id)
    if not user_id:
        return None
    
    user = await db.get(User, user_id)
    if not user or not user.is_active:
        return None
    # print("********************************************")
    # print("DEBUG: user:", user.id, user.username)
    return user


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
