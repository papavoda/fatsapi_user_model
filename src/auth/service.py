import base64
from datetime import datetime, timedelta, timezone
import json
from typing import Optional, Tuple
import uuid
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# 2. JWT через joserfc (НОВОЕ)
from joserfc import jwt
from joserfc.jwk import OctKey
from joserfc.errors import (
    BadSignatureError, ExpiredTokenError, InvalidClaimError, 
    ClaimError, ExpiredTokenError, InvalidTokenError
)

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


class PasswordService:
    """Сервис аутентификации с Argon2"""
    
    @staticmethod
    def verify_password(plain: str, hashed: str) -> bool:
        """Проверка пароля - остаётся с Argon2"""
        try:
            return ph.verify(hashed, plain)
        except VerifyMismatchError:
            return False
        except InvalidHashError:
            return False
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Хеширование пароля с Argon2"""
        return ph.hash(password)
    
    @staticmethod
    def needs_rehash(hashed_password: str) -> bool:
        """Проверка, нужно ли перехешировать (при изменении параметров)"""
        return ph.check_needs_rehash(hashed_password)



class AuthService:

    
    
    """Сервис аутентификации с joserfc"""

    @staticmethod
    def _create_token(
        user_id: uuid.UUID,
        expires_delta: timedelta,
        token_type: str
    ) -> str:
        """Создание JWT токена"""
        current_utc_time = datetime.now(timezone.utc)
        expire_time = current_utc_time + expires_delta
        
        key = OctKey.import_key(AuthConfig.SECRET_KEY)
        
        header = {
            "alg": AuthConfig.ALGORITHM,  # "HS256"
            "typ": "JWT"
        }
        
        claims = {
            "sub": str(user_id),
            "type": token_type,
            "exp": int(expire_time.timestamp()),
            "iat": int(current_utc_time.timestamp())
        }
        
        # Правильный способ: используем jwt.encode() напрямую
        return jwt.encode(header, claims, key)
    
    @staticmethod
    def verify_token(token_str: str) -> Tuple[Optional[dict], Optional[str]]:
        """Верификация токена"""
        try:
            key = OctKey.import_key(AuthConfig.SECRET_KEY)
            

            # print(f"=== DEBUG TOKEN VERIFICATION ===")
            # print(f"Token string (first 50 chars): {token_str[:50]}...")
        
            # # Анализ содержимого токена
            # try:
            #     parts = token_str.split('.')
            #     if len(parts) == 3:
            #         # Декодируем payload (без проверки подписи)
            #         payload_b64 = parts[1]
            #         # Добавляем padding если нужно
            #         payload_b64 += '=' * (4 - len(payload_b64) % 4)
            #         payload_json = base64.urlsafe_b64decode(payload_b64).decode('utf-8')
            #         payload = json.loads(payload_json)
                    
            #         print(f"📦 Raw payload: {payload}")
            #         print(f"🕒 exp value: {payload.get('exp')}")
            #         print(f"📝 exp type: {type(payload.get('exp'))}")
                    
            #         # Текущее время для сравнения
            #         now = int(datetime.now(timezone.utc).timestamp())
            #         print(f"⏰ Current timestamp: {now}")
                    
            #         if 'exp' in payload:
            #             exp_time = payload['exp']
            #             print(f"⏳ Token expires at: {exp_time}")
            #             print(f"🔍 Is expired? {exp_time < now}")
            #             if exp_time < now:
            #                 print("❌ Токен ДОЛЖЕН быть просрочен!")
            #             else:
            #                 print(f"✅ Токен действителен еще {exp_time - now} секунд")
                            
            # except Exception as e:
            #     print(f"⚠️  Error parsing token: {e}")


            token = jwt.decode(
                token_str,
                key,
                algorithms=[AuthConfig.ALGORITHM]
            )
            
            # Получаем claims из токена
            claims = token.claims
            
            # Кастомные проверки
            if claims.get("type") not in ["access", "refresh"]:
                return None, "Invalid token type"           
            if "sub" not in claims:
                return None, "Missing subject claim"
            
            # Standard validation (EXpire check, ...)
            claims_requests = jwt.JWTClaimsRegistry()
            try:
                claims_requests.validate(token.claims)
            except (ClaimError, ExpiredTokenError, InvalidTokenError, Exception) as e:
                return None, f"Invalid token: {str(e)}"
                     
            return dict(claims), None
        
            
        except (BadSignatureError, InvalidTokenError, Exception) as e:
            return None, "Invalid token signature"
        
    
    @staticmethod
    def create_tokens(user_id: uuid.UUID) -> Tuple[str, str]:
        """Создание пары токенов (access, refresh)"""
        access_token = AuthService._create_token(
            user_id=user_id,
            expires_delta=timedelta(minutes=AuthConfig.ACCESS_TOKEN_EXPIRE_MINUTES),
            token_type="access"
        )
        
        refresh_token = AuthService._create_token(
            user_id=user_id,
            expires_delta=timedelta(days=AuthConfig.REFRESH_TOKEN_EXPIRE_DAYS),
            token_type="refresh"
        )
        
        return access_token, refresh_token
    
    @staticmethod
    def refresh_tokens(refresh_token: str) -> Tuple[Optional[Tuple[str, str]], Optional[str]]:
        """
        Обновление токенов
        """
        # Верифицируем refresh token
        claims, error = AuthService.verify_token(refresh_token)
        if error:
            return None, error
        
        # Проверяем что это refresh token
        if not claims or claims.get("type") != "refresh":  # Добавил проверку на None
            return None, "Not a refresh token"
        
        # Создаем новые токены
        try:
            user_id = uuid.UUID(claims["sub"])
            new_access, new_refresh = AuthService.create_tokens(user_id)
            return (new_access, new_refresh), None
        except (ValueError, KeyError):
            print("**************************Invalid user ID in token")
            return None, "Invalid user ID in token"
    
    @staticmethod
    def authenticate_user(db_user: User, password: str) -> bool:
        """Аутентификация пользователя"""
        if not db_user or not db_user.is_active:
            return False
        return PasswordService.verify_password(password, db_user.password)
    
