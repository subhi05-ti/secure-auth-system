import os
from collections.abc import AsyncIterator

import httpx
import pytest
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

# Use test environment variables
os.environ["APP_ENV"] = "testing"
os.environ["JWT_SECRET_KEY"] = "test_secret_key_minimum_32_characters_for_jwt_signing"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

import app.models  # noqa: F401 - Register models
from app.database.base import Base
from app.database.session import get_db
from app.main import app as fastapi_app

test_engine = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    echo=False,
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


@pytest.fixture(autouse=True)
async def prepare_database():
    """Create all tables before each test and drop them after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


@pytest.fixture
async def db_session() -> AsyncIterator[AsyncSession]:
    """Provide isolated database session for a test."""
    async with TestingSessionLocal() as session:
        yield session


@pytest.fixture
async def client() -> AsyncIterator[httpx.AsyncClient]:
    """Provide an asynchronous HTTP test client bound to the FastAPI application."""

    async def override_get_db() -> AsyncIterator[AsyncSession]:
        async with TestingSessionLocal() as session:
            yield session

    fastapi_app.dependency_overrides[get_db] = override_get_db
    transport = httpx.ASGITransport(app=fastapi_app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac
    fastapi_app.dependency_overrides.clear()
