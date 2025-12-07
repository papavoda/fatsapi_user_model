from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple
import uuid
from jose import JWTError, jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

from src.auth.config import AuthConfig
from src.users.models import User

# Настройки Argon2 (рекомендованные OWASP)
ph = PasswordHasher(
    time_cost=3,       # Количество итераций
    memory_cost=65536, # Память в KiB (64 MB)
    parallelism=4,     # Параллельные потоки
    hash_len=32,       # Длина хеша
    salt_len=16        # Длина соли
)

class AuthService:
    """Сервис аутентификации с Argon2"""
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Проверка пароля с Argon2"""
        try:
            return ph.verify(hashed_password, plain_password)
        except (VerifyMismatchError, InvalidHashError):
            return False
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширование пароля с Argon2"""
        return ph.hash(password)
    
    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """Проверка, нужно ли перехешировать (при изменении параметров)"""
        return ph.check_needs_rehash(hashed_password)
    
    @staticmethod
    def create_tokens(user_id: uuid.UUID) -> Tuple[str, str]:
        """Создание пары access + refresh токенов"""
        access_token = AuthService._create_token(
            user_id=user_id,
            expires_delta=AuthConfig.get_access_token_expire(),
            token_type="access"
        )
        
        refresh_token = AuthService._create_token(
            user_id=user_id,
            expires_delta=AuthConfig.get_refresh_token_expire(),
            token_type="refresh"
        )
        
        return access_token, refresh_token
    
    @staticmethod
    def _create_token(
        user_id: uuid.UUID,
        expires_delta: timedelta,
        token_type: str
    ) -> str:
        """Создание JWT токена"""
        current_utc_time = datetime.now(timezone.utc)
        expire = current_utc_time + expires_delta
        
        payload = {
            "sub": str(user_id),
            "exp": expire,
            "type": token_type,
            "iat": current_utc_time
        }
        
        return jwt.encode(payload, AuthConfig.SECRET_KEY, algorithm=AuthConfig.ALGORITHM)
    
    @staticmethod
    def decode_token(token: str) -> Optional[uuid.UUID]:
        """Декодирование токена, возвращает user_id или None"""
        try:
            payload = jwt.decode(token, AuthConfig.SECRET_KEY, algorithms=[AuthConfig.ALGORITHM])
            user_id_str = payload.get("sub")  # ← Без типа, будет Optional[str]
            
            if not user_id_str or not isinstance(user_id_str, str):
                return None
            
            return uuid.UUID(user_id_str)
            
        except (JWTError, ValueError):
            return None
    
    @staticmethod
    def authenticate_user(db_user: User, password: str) -> bool:
        """Аутентификация пользователя"""
        if not db_user or not db_user.is_active:
            return False
        return AuthService.verify_password(password, db_user.password)
    
