from datetime import datetime
from typing import AsyncGenerator
from uuid import UUID, uuid4
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, AsyncAttrs, async_sessionmaker
from sqlalchemy.sql.functions import func
from sqlmodel import SQLModel, Field
from app.core import settings


class OAuthBaseModel(SQLModel, AsyncAttrs):
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    created_at: datetime = Field(default=func.now(), index=True)
    updated_at: datetime = Field(default=func.now(), index=True)

engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,  # Recycle connections after 30 minutes
    pool_pre_ping=True  # Verify connection is still alive before using
)
async_session = async_sessionmaker(engine, expire_on_commit=False)  # support multiple commits

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Get database session."""
    async with async_session() as session:
        try:
            yield session
        finally:
            await session.close()


__all__ = ['engine', 'AsyncSession', 'OAuthBaseModel', 'get_db']