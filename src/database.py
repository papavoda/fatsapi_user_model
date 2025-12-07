# src/database.py - db connection related stuff
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker
from sqlalchemy import String
from src.config import settings
from sqlalchemy.orm import DeclarativeBase, mapped_column
from typing import Annotated, AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession

async_engine = create_async_engine(
    url=settings.DATABASE_URL_asyncpg,
    pool_size=20,
    max_overflow=30,
    pool_pre_ping=True,
    echo=True  # Включайте только для отладки
)

async_session_factory = async_sessionmaker(
    async_engine,
    expire_on_commit=False  # ← Добавьте это для безопасности
)

# Session lifecycle should be controlled externally; 
# repository/services must not create their own session.
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session


# int_pk = Annotated[int, mapped_column(primary_key=True)]
# uuid_pk = Annotated[uuid.UUID, mapped_column(primary_key=True, default=uuid.uuid4)]
str_64 = Annotated[str, 50]
str_256 = Annotated[str, 256]
int_pk = Annotated[int, mapped_column(primary_key=True)]
class Base(DeclarativeBase):
    type_annotation_map = {
        int_pk: int,
        str_64: String(50),
        str_256: String(256),
    }
    # repr_cols_num = 3
    # repr_cols = ()
    """ Relationships are not included in __repr__ !!!!
        т.к. могут привести к неожиданным подгрузкам
    
    """
    # __repr__ для всех моделей
    # def __repr__(self):
    #     cols = []
    #     for idx, col in enumerate(self.__table__.columns.keys()):
    #         if col in self.repr_cols or idx < self.repr_cols_num:
    #             cols.append(f"{col}={getattr(self, col)}")

    #     return f"<<{self.__class__.__name__} {', '.join(cols)}>>"