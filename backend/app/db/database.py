"""
Database engine, ORM models, and session factory.

Swap DATABASE_URL in .env to move from SQLite → PostgreSQL.
No dialect-specific SQL anywhere — all ORM.
"""
from datetime import datetime
from sqlalchemy import String, Float, DateTime, Text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.config import settings


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    level: Mapped[str] = mapped_column(String(20), nullable=False)
    ml_probability: Mapped[float] = mapped_column(Float, nullable=False)
    indicators_json: Mapped[str] = mapped_column(Text, default="[]")
    explanation_json: Mapped[str] = mapped_column(Text, default="[]")
    cti_json: Mapped[str] = mapped_column(Text, default="{}")
    features_json: Mapped[str] = mapped_column(Text, default="{}")
    source: Mapped[str] = mapped_column(String(20), default="api")
    scanned_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


engine = create_async_engine(settings.database_url, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_session() -> AsyncSession:  # type: ignore[misc]
    async with AsyncSessionLocal() as session:
        yield session
