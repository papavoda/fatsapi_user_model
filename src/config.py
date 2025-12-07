# src/config.py # global configs
from typing import List, Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    DB_HOST: str = "localhost"
    DB_PORT: int = 5432
    DB_USER: str = "user"
    DB_PASSWORD: str = "password"
    DB_NAME: str = "db"

# Настройки для production (можно вынести в env)
    ARGON2_TIME_COST: int = 3          # opslimit
    ARGON2_MEMORY_COST: int = 65536    # memlimit (64MB)
    ARGON2_PARALLELISM: int = 4        # threads


    JWT_SECRET_KEY: str  = ""
    ALGORITHM: str = "HS256"
    # Время жизни токенов
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7


    ALLOWED_HOSTS: List[str] = ["localhost",]
    # Разрешенные хосты
    
    
    # CORS настройки
    BACKEND_CORS_ORIGINS: List[str] = []
    ALLOW_ORIGIN_REGEX: Optional[str] = None
    
    # Безопасные методы по умолчанию
    ALLOWED_METHODS: List[str] = ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"]
    
    # Основные заголовки
    ALLOWED_HEADERS: List[str] = [
        "Authorization",
        "Content-Type",
        "Accept",
        "Origin",
        "User-Agent",
        "DNT",
        "Cache-Control",
        "X-Requested-With",
        "X-CSRF-Token",
        "Access-Control-Allow-Headers",
        "access-control-allow-origin",
    ]
    
    EXPOSE_HEADERS: List[str] = ["Content-Range", "X-Total-Count"]
    CORS_MAX_AGE: int = 600  # 10 минут

    # for asyncpg
    @property
    def DATABASE_URL_asyncpg(self):
        return f"postgresql+asyncpg://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"

    model_config = SettingsConfigDict(env_file=".env")



settings = Settings()
