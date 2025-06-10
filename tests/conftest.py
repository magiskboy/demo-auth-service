"""
Test configuration and fixtures for OAuth2 service.

This module provides pytest fixtures and configuration for testing the OAuth2 service
with async SQLAlchemy and isolated test database.
"""

import os
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel

from app.core.db import OAuthBaseModel
from app.users.models import User, LinkedAccount
from app.rbac.models import Role, Permission, UserRole, RolePermission
from app.users.services import UserService
from app.rbac.services import RoleService, PermissionService, RBACService
from app.users.schemas import UserCreate, UserUpdate, LinkedAccountCreate
from app.rbac.schemas import RoleCreate, PermissionCreate, RoleUpdate, PermissionUpdate, RoleFilter, PermissionFilter


# Test database URL - use a separate test database
TEST_DATABASE_URL = os.getenv(
    "TEST_DATABASE_URL", 
    "postgresql+asyncpg://postgres:postgres@localhost:5432/test_oauth2_service"
)

# Create test engine with NullPool for better test isolation
test_engine = create_async_engine(
    TEST_DATABASE_URL,
    echo=False,  # Set to True for SQL debugging
    poolclass=NullPool,  # Disable connection pooling for tests
)

TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


@pytest_asyncio.fixture(autouse=True)
async def setup_test_database(request):
    """
    Setup test database schema before each test and cleanup after.
    This fixture runs for each test to ensure isolation.
    Only runs for integration tests, not unit tests.
    """
    # Skip database setup for unit tests
    if "unit" in str(request.fspath):
        yield
        return
    
    # Create all tables
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    yield
    
    # Drop all tables (this ensures clean state for each test)
    async with test_engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Create a fresh database session for each test.
    All database operations are rolled back after each test.
    """
    async with TestSessionLocal() as session:
        try:
            yield session
        finally:
            # Session cleanup is handled by the context manager
            pass


# Service fixtures
@pytest_asyncio.fixture
async def user_service(db_session: AsyncSession) -> UserService:
    """Create a UserService instance for testing."""
    return UserService(db_session)


@pytest_asyncio.fixture
async def role_service(db_session: AsyncSession) -> RoleService:
    """Create a RoleService instance for testing."""
    return RoleService(db_session)


@pytest_asyncio.fixture
async def permission_service(db_session: AsyncSession) -> PermissionService:
    """Create a PermissionService instance for testing."""
    return PermissionService(db_session)


@pytest_asyncio.fixture
async def rbac_service(db_session: AsyncSession) -> RBACService:
    """Create a RBACService instance for testing."""
    return RBACService(db_session)


# Data creation fixtures
@pytest_asyncio.fixture
async def created_user(user_service: UserService) -> User:
    """Create a test user in the database."""
    user_create = UserCreate(email="test@example.com", name="Test User", password="password123")
    return await user_service.create_user(user_create)


@pytest_asyncio.fixture
async def created_role(role_service: RoleService) -> Role:
    """Create a test role in the database."""
    role_create = RoleCreate(name="test-role", description="Test role description")
    return await role_service.create_role(role_create)


@pytest_asyncio.fixture
async def created_permission(permission_service: PermissionService) -> Permission:
    """Create a test permission in the database."""
    permission_create = PermissionCreate(name="test-permission", description="Test permission description")
    return await permission_service.create_permission(permission_create)


# Schema fixtures - these are not async since they're just data objects
@pytest.fixture
def sample_user_create() -> UserCreate:
    """Create a sample UserCreate object."""
    return UserCreate(email="sample@example.com", name="Sample User", password="samplepass123")


@pytest.fixture
def sample_role_create() -> RoleCreate:
    """Create a sample RoleCreate object."""
    return RoleCreate(name="sample-role", description="Sample role for testing")


@pytest.fixture
def sample_permission_create() -> PermissionCreate:
    """Create a sample PermissionCreate object."""
    return PermissionCreate(name="sample-permission", description="Sample permission for testing")


@pytest.fixture
def sample_linked_account_create() -> LinkedAccountCreate:
    """Create a sample LinkedAccountCreate object."""
    return LinkedAccountCreate(
        provider="google",
        given_name="Test",
        family_name="User",
        picture="https://example.com/avatar.jpg",
        email="test@example.com",
        sub="google-sub-sample"
    )


# Mock fixtures for external dependencies
@pytest.fixture
def mock_hash_password():
    """Mock password hashing function."""
    return AsyncMock(return_value="hashed_password")


# Pytest configuration hooks
def pytest_configure(config):
    """Configure pytest with custom markers and settings."""
    config.addinivalue_line(
        "markers", "unit: mark test as a unit test"
    )
    config.addinivalue_line(
        "markers", "integration: mark test as an integration test"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )
    config.addinivalue_line(
        "markers", "auth: mark test as authentication related"
    )
    config.addinivalue_line(
        "markers", "db: mark test as database related"
    )
    config.addinivalue_line(
        "markers", "rbac: mark test as RBAC related"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark tests based on their location and name."""
    for item in items:
        # Mark tests in unit/ directory as unit tests
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        
        # Mark tests in integration/ directory as integration tests
        if "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        
        # Mark auth-related tests
        if "auth" in str(item.fspath) or "auth" in item.name:
            item.add_marker(pytest.mark.auth)
        
        # Mark database-related tests
        if any(keyword in str(item.fspath) for keyword in ["models", "crud", "db", "test_users", "test_rbac"]):
            item.add_marker(pytest.mark.db)
        
        # Mark RBAC-related tests
        if "rbac" in str(item.fspath) or "rbac" in item.name:
            item.add_marker(pytest.mark.rbac) 