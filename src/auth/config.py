from datetime import timedelta
from src.config import settings

class AuthConfig:
    SECRET_KEY = settings.JWT_SECRET_KEY
    ALGORITHM = settings.ALGORITHM
    ACCESS_TOKEN_EXPIRE_MINUTES = settings.ACCESS_TOKEN_EXPIRE_MINUTES
    REFRESH_TOKEN_EXPIRE_DAYS = settings.REFRESH_TOKEN_EXPIRE_DAYS

    """Конфигурация аутентификации"""    
    # @classmethod
    # def get_access_token_expire(cls) -> timedelta:
    #     return timedelta(minutes=cls.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    # @classmethod
    # def get_refresh_token_expire(cls) -> timedelta:
    #     return timedelta(days=cls.REFRESH_TOKEN_EXPIRE_DAYS)
    