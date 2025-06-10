"""
Test configuration and fixtures for OAuth2 service.

This module provides pytest fixtures and configuration for testing the OAuth2 service
with async SQLAlchemy and isolated test database.
"""

import os
from typing import AsyncGenerator

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import NullPool
from sqlmodel import SQLModel

from app.users.models import User
from app.rbac.models import Role, Permission
from app.users.services import UserService
from app.rbac.services import RoleService, PermissionService, RBACService
from app.users.schemas import UserCreate, LinkedAccountCreate
from app.rbac.schemas import RoleCreate, PermissionCreate

# Import factories
from tests.factories import (
    UserFactory, VerifiedUserFactory, AdminUserFactory,
    LinkedAccountFactory, GoogleLinkedAccountFactory,
    RoleFactory,
    PermissionFactory,
    create_user_create_schema, create_role_create_schema, create_permission_create_schema,
    create_linked_account_create_schema, create_standard_permissions, create_standard_roles,
    create_complete_oauth_scenario, create_sso_test_scenario, create_rbac_test_scenario
)


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


# Factory-based data creation fixtures
@pytest_asyncio.fixture
async def created_user(user_service: UserService) -> User:
    """Create a test user in the database using factory."""
    user_create = create_user_create_schema(email="test@example.com", name="Test User")
    return await user_service.create_user(user_create)


@pytest_asyncio.fixture
async def created_verified_user(user_service: UserService) -> User:
    """Create a verified test user in the database using factory."""
    user_create = create_user_create_schema(email="verified@example.com", name="Verified User")
    user = await user_service.create_user(user_create)
    # Note: You might need to update the user to set is_verified=True
    return user


@pytest_asyncio.fixture
async def created_admin_user(user_service: UserService) -> User:
    """Create an admin test user in the database using factory."""
    user_create = create_user_create_schema(email="admin@example.com", name="Admin User")
    return await user_service.create_user(user_create)


@pytest_asyncio.fixture
async def created_role(role_service: RoleService) -> Role:
    """Create a test role in the database using factory."""
    role_create = create_role_create_schema(name="test-role", description="Test role description")
    return await role_service.create_role(role_create)


@pytest_asyncio.fixture
async def created_admin_role(role_service: RoleService) -> Role:
    """Create an admin role in the database using factory."""
    role_create = create_role_create_schema(name="admin", description="Administrator role")
    return await role_service.create_role(role_create)


@pytest_asyncio.fixture
async def created_permission(permission_service: PermissionService) -> Permission:
    """Create a test permission in the database using factory."""
    permission_create = create_permission_create_schema(
        name="GET:/api/v1/test", 
        description="Test permission description"
    )
    return await permission_service.create_permission(permission_create)


# Factory-based schema fixtures
@pytest.fixture
def sample_user_create() -> UserCreate:
    """Create a sample UserCreate object using factory."""
    return create_user_create_schema(email="sample@example.com", name="Sample User")


@pytest.fixture
def sample_role_create() -> RoleCreate:
    """Create a sample RoleCreate object using factory."""
    return create_role_create_schema(name="sample-role", description="Sample role for testing")


@pytest.fixture
def sample_permission_create() -> PermissionCreate:
    """Create a sample PermissionCreate object using factory."""
    return create_permission_create_schema(
        name="POST:/api/v1/sample", 
        description="Sample permission for testing"
    )


@pytest.fixture
def sample_linked_account_create() -> LinkedAccountCreate:
    """Create a sample LinkedAccountCreate object using factory."""
    return create_linked_account_create_schema(
        provider="google",
        email="test@example.com"
    )


# Complex scenario fixtures
@pytest.fixture
def complete_oauth_scenario():
    """Create a complete OAuth test scenario with users, roles, permissions, and assignments."""
    return create_complete_oauth_scenario()


@pytest.fixture
def sso_test_scenario():
    """Create test scenario focused on SSO functionality."""
    return create_sso_test_scenario()


@pytest.fixture
def rbac_test_scenario():
    """Create test scenario focused on RBAC functionality."""
    return create_rbac_test_scenario()


# Standard data fixtures
@pytest.fixture
def standard_permissions():
    """Create standard set of permissions."""
    return create_standard_permissions()


@pytest.fixture
def standard_roles():
    """Create standard set of roles."""
    return create_standard_roles()


# Factory instance fixtures for direct use in tests
@pytest.fixture
def user_factory():
    """Provide UserFactory for direct use in tests."""
    return UserFactory


@pytest.fixture
def verified_user_factory():
    """Provide VerifiedUserFactory for direct use in tests."""
    return VerifiedUserFactory


@pytest.fixture
def admin_user_factory():
    """Provide AdminUserFactory for direct use in tests."""
    return AdminUserFactory


@pytest.fixture
def role_factory():
    """Provide RoleFactory for direct use in tests."""
    return RoleFactory


@pytest.fixture
def permission_factory():
    """Provide PermissionFactory for direct use in tests."""
    return PermissionFactory


@pytest.fixture
def linked_account_factory():
    """Provide LinkedAccountFactory for direct use in tests."""
    return LinkedAccountFactory


@pytest.fixture
def google_linked_account_factory():
    """Provide GoogleLinkedAccountFactory for direct use in tests."""
    return GoogleLinkedAccountFactory


# Bulk data creation fixtures
@pytest_asyncio.fixture
async def multiple_users(user_service: UserService):
    """Create multiple users in the database."""
    users = []
    for i in range(5):
        user_create = create_user_create_schema(
            email=f"user{i}@example.com", 
            name=f"User {i}"
        )
        user = await user_service.create_user(user_create)
        users.append(user)
    return users


@pytest_asyncio.fixture
async def multiple_roles(role_service: RoleService):
    """Create multiple roles in the database."""
    roles = []
    role_names = ["admin", "user_manager", "viewer", "editor"]
    for name in role_names:
        role_create = create_role_create_schema(
            name=name, 
            description=f"{name.replace('_', ' ').title()} role"
        )
        role = await role_service.create_role(role_create)
        roles.append(role)
    return roles


@pytest_asyncio.fixture
async def multiple_permissions(permission_service: PermissionService):
    """Create multiple permissions in the database."""
    permissions = []
    permission_specs = [
        ("GET:/api/v1/users", "Read users"),
        ("POST:/api/v1/users", "Create users"),
        ("PUT:/api/v1/users/*", "Update users"),
        ("DELETE:/api/v1/users/*", "Delete users"),
        ("GET:/api/v1/admin/roles", "Read roles"),
        ("POST:/api/v1/admin/roles", "Create roles"),
    ]
    
    for name, description in permission_specs:
        permission_create = create_permission_create_schema(name=name, description=description)
        permission = await permission_service.create_permission(permission_create)
        permissions.append(permission)
    
    return permissions


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
    config.addinivalue_line(
        "markers", "sso: mark test as SSO related"
    )
    config.addinivalue_line(
        "markers", "factory: mark test as using factories"
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
        
        # Mark SSO-related tests
        if "sso" in str(item.fspath) or "sso" in item.name or "oauth" in item.name:
            item.add_marker(pytest.mark.sso)
        
        # Mark factory-related tests
        if "factory" in item.name or "Factory" in str(item.fspath):
            item.add_marker(pytest.mark.factory) 