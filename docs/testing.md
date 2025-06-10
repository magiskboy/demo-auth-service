# Testing Guide

## Overview

The OAuth2 Service implements a comprehensive testing strategy focused on **reliability**, **maintainability**, and **speed**. Our testing approach emphasizes factory-based test data generation, async testing patterns, and comprehensive coverage of authentication and authorization flows.

## 🧪 Testing Philosophy

### Principles
- **Test Pyramid**: Unit tests form the foundation, with integration and E2E tests providing confidence
- **Factory Pattern**: Consistent, realistic test data generation
- **Async-First**: All tests support asynchronous operations
- **Isolation**: Each test is independent and can run in parallel
- **Real Database**: Tests use actual PostgreSQL for realistic scenarios

### Testing Types
1. **Unit Tests**: Individual component testing (services, utilities)
2. **Integration Tests**: Database operations and API endpoints
3. **Authentication Tests**: OAuth2 flows and token validation
4. **RBAC Tests**: Permission and role validation
5. **Security Tests**: Authentication bypass and authorization checks

## 🏗️ Test Infrastructure

### Test Configuration (`conftest.py`)

```python
# tests/conftest.py
import pytest
import asyncio
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from fastapi.testclient import TestClient

from app.main import app
from app.core.database import get_db_session
from app.core.config import get_settings

# Test database configuration
TEST_DATABASE_URL = "postgresql+asyncpg://test_user:test_pass@localhost/test_oauth2_db"

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def test_engine():
    """Create test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)
    
    yield engine
    
    # Drop all tables after tests
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.drop_all)
    
    await engine.dispose()

@pytest.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create database session for each test."""
    session_factory = sessionmaker(
        test_engine, 
        class_=AsyncSession, 
        expire_on_commit=False
    )
    
    async with session_factory() as session:
        yield session
        await session.rollback()

@pytest.fixture
def client(db_session: AsyncSession) -> TestClient:
    """Create FastAPI test client with database override."""
    def override_get_db():
        return db_session
    
    app.dependency_overrides[get_db_session] = override_get_db
    client = TestClient(app)
    
    yield client
    
    # Clean up overrides
    app.dependency_overrides.clear()

@pytest.fixture
def anyio_backend():
    """Configure async test backend."""
    return "asyncio"
```

### Test Settings

```python
# tests/test_config.py
from app.core.config import Settings

def get_test_settings() -> Settings:
    """Test-specific configuration."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        redis_url="redis://localhost:6379/1",  # Test database
        secret_key="test-secret-key-for-testing-only",
        access_token_expire_minutes=30,
        refresh_token_expire_minutes=7 * 24 * 60,
        environment="testing",
        log_level="DEBUG"
    )
```

## 🏭 Factory Pattern Implementation

### Base Factory Setup

```python
# tests/factories/__init__.py
import factory
from faker import Faker
from typing import Type, TypeVar
from uuid import uuid4
from datetime import datetime, timezone

fake = Faker()
T = TypeVar('T')

class BaseFactory(factory.Factory):
    """Base factory with common functionality."""
    
    id = factory.LazyFunction(lambda: str(uuid4()))
    created_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    updated_at = factory.LazyFunction(lambda: datetime.now(timezone.utc))
    
    @classmethod
    def create_batch_async(cls, size: int, **kwargs) -> list[T]:
        """Create multiple instances for async operations."""
        return [cls.build(**kwargs) for _ in range(size)]
```

### User Factory

```python
# tests/factories/user_factory.py
import factory
from passlib.context import CryptContext
from app.users.models import User
from . import BaseFactory, fake

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class UserFactory(BaseFactory):
    """Factory for creating test users."""
    
    class Meta:
        model = User
    
    email = factory.LazyAttribute(lambda obj: fake.unique.email())
    name = factory.LazyAttribute(lambda obj: fake.name())
    hashed_password = factory.LazyAttribute(
        lambda obj: pwd_context.hash("TestPassword123!")
    )
    is_active = True
    is_verified = False
    
    @factory.post_generation
    def roles(self, create, extracted, **kwargs):
        """Add roles to user after creation."""
        if not create:
            return
        
        if extracted:
            for role in extracted:
                self.roles.append(role)

class AdminUserFactory(UserFactory):
    """Factory for admin users."""
    
    email = factory.LazyAttribute(lambda obj: f"admin.{fake.user_name()}@example.com")
    is_verified = True
    
    @factory.post_generation
    def admin_roles(self, create, extracted, **kwargs):
        """Automatically assign admin role."""
        if create:
            admin_role = RoleFactory(name="admin")
            self.roles.append(admin_role)

class InactiveUserFactory(UserFactory):
    """Factory for inactive users."""
    
    is_active = False
    email = factory.LazyAttribute(lambda obj: f"inactive.{fake.user_name()}@example.com")
```

### RBAC Factories

```python
# tests/factories/rbac_factory.py
import factory
from app.rbac.models import Role, Permission, UserRole, RolePermission
from . import BaseFactory, fake

class PermissionFactory(BaseFactory):
    """Factory for creating permissions."""
    
    class Meta:
        model = Permission
    
    name = factory.LazyAttribute(
        lambda obj: f"{fake.random_element(['GET', 'POST', 'PUT', 'DELETE'])}:/api/v1/{fake.word()}"
    )
    description = factory.LazyAttribute(lambda obj: fake.sentence())

class RoleFactory(BaseFactory):
    """Factory for creating roles."""
    
    class Meta:
        model = Role
    
    name = factory.LazyAttribute(lambda obj: fake.unique.word().lower())
    description = factory.LazyAttribute(lambda obj: fake.sentence())
    
    @factory.post_generation
    def permissions(self, create, extracted, **kwargs):
        """Add permissions to role after creation."""
        if not create:
            return
        
        if extracted:
            for permission in extracted:
                self.permissions.append(permission)

class AdminRoleFactory(RoleFactory):
    """Factory for admin role with full permissions."""
    
    name = "admin"
    description = "Full system administrator"
    
    @factory.post_generation
    def admin_permissions(self, create, extracted, **kwargs):
        """Add all admin permissions."""
        if create:
            admin_permissions = [
                PermissionFactory(name="GET:/api/v1/users"),
                PermissionFactory(name="POST:/api/v1/users"),
                PermissionFactory(name="PUT:/api/v1/users"),
                PermissionFactory(name="DELETE:/api/v1/users"),
                PermissionFactory(name="GET:/api/v1/admin/roles"),
                PermissionFactory(name="POST:/api/v1/admin/roles"),
            ]
            self.permissions.extend(admin_permissions)

class UserRoleFactory(BaseFactory):
    """Factory for user-role associations."""
    
    class Meta:
        model = UserRole
    
    user_id = factory.LazyAttribute(lambda obj: str(UserFactory().id))
    role_id = factory.LazyAttribute(lambda obj: str(RoleFactory().id))
```

### Authentication Factories

```python
# tests/factories/auth_factory.py
import factory
from datetime import datetime, timedelta, timezone
from jose import jwt
from app.auth.models import LinkedAccount
from app.core.config import get_settings
from . import BaseFactory, fake

settings = get_settings()

class LinkedAccountFactory(BaseFactory):
    """Factory for OAuth linked accounts."""
    
    class Meta:
        model = LinkedAccount
    
    provider = factory.LazyAttribute(lambda obj: fake.random_element(["google", "github"]))
    provider_user_id = factory.LazyAttribute(lambda obj: fake.uuid4())
    email = factory.LazyAttribute(lambda obj: fake.email())
    name = factory.LazyAttribute(lambda obj: fake.name())
    avatar_url = factory.LazyAttribute(lambda obj: fake.image_url())
    user_id = factory.LazyAttribute(lambda obj: str(UserFactory().id))

class TokenFactory(factory.Factory):
    """Factory for creating JWT tokens."""
    
    class Meta:
        model = dict  # Returns dictionary with token data
    
    user_id = factory.LazyAttribute(lambda obj: str(UserFactory().id))
    email = factory.LazyAttribute(lambda obj: fake.email())
    
    @classmethod
    def create_access_token(cls, user_id: str, email: str, **kwargs) -> str:
        """Create a valid access token."""
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.access_token_expire_minutes
        )
        
        payload = {
            "sub": user_id,
            "email": email,
            "exp": expire,
            "type": "access",
            **kwargs
        }
        
        return jwt.encode(payload, settings.secret_key, algorithm="HS256")
    
    @classmethod
    def create_refresh_token(cls, user_id: str, **kwargs) -> str:
        """Create a valid refresh token."""
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.refresh_token_expire_minutes
        )
        
        payload = {
            "sub": user_id,
            "exp": expire,
            "type": "refresh",
            **kwargs
        }
        
        return jwt.encode(payload, settings.secret_key, algorithm="HS256")
    
    @classmethod
    def create_expired_token(cls, user_id: str) -> str:
        """Create an expired token for testing."""
        expire = datetime.now(timezone.utc) - timedelta(minutes=30)
        
        payload = {
            "sub": user_id,
            "exp": expire,
            "type": "access"
        }
        
        return jwt.encode(payload, settings.secret_key, algorithm="HS256")
```

## 🔐 Authentication Testing

### OAuth2 Flow Testing

```python
# tests/test_auth.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch, MagicMock

from app.auth.services import AuthService
from app.users.models import User
from tests.factories.user_factory import UserFactory
from tests.factories.auth_factory import TokenFactory

class TestAuthenticationFlow:
    """Test OAuth2 authentication flows."""
    
    @pytest.mark.asyncio
    async def test_user_registration(self, client: TestClient, db_session: AsyncSession):
        """Test user registration flow."""
        user_data = {
            "email": "newuser@example.com",
            "password": "SecurePassword123!",
            "name": "New User"
        }
        
        response = client.post("/api/v1/auth/register", json=user_data)
        
        assert response.status_code == 201
        data = response.json()
        assert data["email"] == user_data["email"]
        assert data["name"] == user_data["name"]
        assert "access_token" in data
        assert "refresh_token" in data
    
    @pytest.mark.asyncio
    async def test_user_login_success(self, client: TestClient, db_session: AsyncSession):
        """Test successful user login."""
        # Create test user
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        login_data = {
            "email": user.email,
            "password": "TestPassword123!"  # Default factory password
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
    
    @pytest.mark.asyncio
    async def test_user_login_invalid_credentials(self, client: TestClient):
        """Test login with invalid credentials."""
        login_data = {
            "email": "nonexistent@example.com",
            "password": "wrongpassword"
        }
        
        response = client.post("/api/v1/auth/login", json=login_data)
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_token_refresh(self, client: TestClient, db_session: AsyncSession):
        """Test token refresh flow."""
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        # Create valid refresh token
        refresh_token = TokenFactory.create_refresh_token(str(user.id))
        
        response = client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    @pytest.mark.asyncio
    async def test_protected_endpoint_access(self, client: TestClient, db_session: AsyncSession):
        """Test accessing protected endpoints with valid token."""
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        # Create valid access token
        access_token = TokenFactory.create_access_token(str(user.id), user.email)
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["email"] == user.email
    
    @pytest.mark.asyncio
    async def test_token_expiry(self, client: TestClient, db_session: AsyncSession):
        """Test behavior with expired tokens."""
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        # Create expired token
        expired_token = TokenFactory.create_expired_token(str(user.id))
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {expired_token}"}
        )
        
        assert response.status_code == 401
        assert "Token expired" in response.json()["detail"]

class TestOAuth2SSO:
    """Test OAuth2 SSO flows."""
    
    def test_google_oauth_initiation(self, client: TestClient):
        """Test Google OAuth initiation."""
        response = client.get("/api/v1/auth/login/google")
        
        assert response.status_code == 302
        location = response.headers["location"]
        assert "accounts.google.com" in location
        assert "client_id" in location
        assert "scope=openid%20email%20profile" in location
    
    @patch('app.auth.services.oauth2_client')
    @pytest.mark.asyncio
    async def test_google_oauth_callback_success(
        self, 
        mock_oauth_client, 
        client: TestClient, 
        db_session: AsyncSession
    ):
        """Test successful Google OAuth callback."""
        # Mock Google OAuth response
        mock_token = MagicMock()
        mock_token.get.return_value = {
            "sub": "google-user-123",
            "email": "user@gmail.com",
            "name": "Google User",
            "picture": "https://example.com/avatar.jpg"
        }
        mock_oauth_client.google.authorize_access_token.return_value = mock_token
        
        response = client.get(
            "/api/v1/auth/callback/google",
            params={"code": "auth_code", "state": "random_state"}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
    
    @patch('app.auth.services.oauth2_client')
    @pytest.mark.asyncio
    async def test_google_oauth_account_linking(
        self, 
        mock_oauth_client, 
        client: TestClient, 
        db_session: AsyncSession
    ):
        """Test linking Google account to existing user."""
        # Create existing user
        existing_user = UserFactory(email="user@gmail.com")
        db_session.add(existing_user)
        await db_session.commit()
        
        # Mock Google OAuth response with same email
        mock_token = MagicMock()
        mock_token.get.return_value = {
            "sub": "google-user-123",
            "email": "user@gmail.com",
            "name": "Google User",
            "picture": "https://example.com/avatar.jpg"
        }
        mock_oauth_client.google.authorize_access_token.return_value = mock_token
        
        response = client.get(
            "/api/v1/auth/callback/google",
            params={"code": "auth_code", "state": "random_state"}
        )
        
        assert response.status_code == 200
        
        # Verify account was linked
        from app.auth.models import LinkedAccount
        statement = select(LinkedAccount).where(LinkedAccount.user_id == existing_user.id)
        result = await db_session.exec(statement)
        linked_account = result.first()
        
        assert linked_account is not None
        assert linked_account.provider == "google"
        assert linked_account.provider_user_id == "google-user-123"
```

## 🛡️ RBAC Testing

```python
# tests/test_rbac.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi.testclient import TestClient

from app.rbac.services import RBACService
from tests.factories.user_factory import UserFactory, AdminUserFactory
from tests.factories.rbac_factory import RoleFactory, PermissionFactory, AdminRoleFactory
from tests.factories.auth_factory import TokenFactory

class TestRBACService:
    """Test RBAC service functionality."""
    
    @pytest.mark.asyncio
    async def test_user_has_permission_direct(self, db_session: AsyncSession):
        """Test user permission check through direct role assignment."""
        # Create user, role, and permission
        user = UserFactory()
        permission = PermissionFactory(name="GET:/api/v1/users")
        role = RoleFactory(permissions=[permission])
        user.roles.append(role)
        
        db_session.add_all([user, role, permission])
        await db_session.commit()
        
        rbac_service = RBACService(db_session)
        
        # Test permission check
        has_permission = await rbac_service.user_has_permission(
            user.id, 
            "GET:/api/v1/users"
        )
        
        assert has_permission is True
    
    @pytest.mark.asyncio
    async def test_user_lacks_permission(self, db_session: AsyncSession):
        """Test user permission check when permission is not granted."""
        user = UserFactory()
        role = RoleFactory()  # Role without permissions
        user.roles.append(role)
        
        db_session.add_all([user, role])
        await db_session.commit()
        
        rbac_service = RBACService(db_session)
        
        has_permission = await rbac_service.user_has_permission(
            user.id, 
            "GET:/api/v1/admin/users"
        )
        
        assert has_permission is False
    
    @pytest.mark.asyncio
    async def test_role_permission_assignment(self, db_session: AsyncSession):
        """Test assigning permissions to roles."""
        role = RoleFactory()
        permission = PermissionFactory()
        admin_user = AdminUserFactory()
        
        db_session.add_all([role, permission, admin_user])
        await db_session.commit()
        
        rbac_service = RBACService(db_session)
        
        # Assign permission to role
        result = await rbac_service.assign_permission_to_role(
            role.id,
            permission.id,
            str(admin_user.id)
        )
        
        assert result is True
        
        # Verify assignment
        updated_role = await rbac_service.get_role(role.id, str(admin_user.id))
        assert len(updated_role.permissions) == 1
        assert updated_role.permissions[0].id == permission.id

class TestRBACEndpoints:
    """Test RBAC API endpoints."""
    
    @pytest.mark.asyncio
    async def test_create_role_as_admin(self, client: TestClient, db_session: AsyncSession):
        """Test role creation by admin user."""
        admin_user = AdminUserFactory()
        db_session.add(admin_user)
        await db_session.commit()
        
        access_token = TokenFactory.create_access_token(str(admin_user.id), admin_user.email)
        
        role_data = {
            "name": "new_role",
            "description": "A new test role"
        }
        
        response = client.post(
            "/api/v1/admin/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["name"] == role_data["name"]
        assert data["description"] == role_data["description"]
    
    @pytest.mark.asyncio
    async def test_create_role_unauthorized(self, client: TestClient, db_session: AsyncSession):
        """Test role creation by non-admin user."""
        regular_user = UserFactory()
        db_session.add(regular_user)
        await db_session.commit()
        
        access_token = TokenFactory.create_access_token(str(regular_user.id), regular_user.email)
        
        role_data = {
            "name": "unauthorized_role",
            "description": "Should not be created"
        }
        
        response = client.post(
            "/api/v1/admin/roles",
            json=role_data,
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 403
        assert "Insufficient permissions" in response.json()["detail"]
    
    @pytest.mark.asyncio
    async def test_assign_role_to_user(self, client: TestClient, db_session: AsyncSession):
        """Test assigning role to user."""
        admin_user = AdminUserFactory()
        target_user = UserFactory()
        role = RoleFactory()
        
        db_session.add_all([admin_user, target_user, role])
        await db_session.commit()
        
        access_token = TokenFactory.create_access_token(str(admin_user.id), admin_user.email)
        
        response = client.post(
            f"/api/v1/admin/users/{target_user.id}/roles",
            json={"role_id": str(role.id)},
            headers={"Authorization": f"Bearer {access_token}"}
        )
        
        assert response.status_code == 200
        
        # Verify assignment in database
        await db_session.refresh(target_user)
        assert len(target_user.roles) > 0
        assert any(r.id == role.id for r in target_user.roles)
```

## 🧪 Service Layer Testing

```python
# tests/test_user_service.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from unittest.mock import patch

from app.users.services import UserService
from app.users.schemas import UserCreate, UserUpdate
from tests.factories.user_factory import UserFactory

class TestUserService:
    """Test user service business logic."""
    
    @pytest.mark.asyncio
    async def test_create_user_success(self, db_session: AsyncSession):
        """Test successful user creation."""
        user_service = UserService(db_session)
        
        user_data = UserCreate(
            email="newuser@example.com",
            name="New User",
            password="SecurePassword123!"
        )
        
        user = await user_service.create_user(user_data)
        
        assert user.email == user_data.email
        assert user.name == user_data.name
        assert user.is_active is True
        assert user.is_verified is False
        assert user.hashed_password is not None
        assert user.hashed_password != user_data.password  # Should be hashed
    
    @pytest.mark.asyncio
    async def test_create_user_duplicate_email(self, db_session: AsyncSession):
        """Test user creation with duplicate email."""
        # Create existing user
        existing_user = UserFactory(email="existing@example.com")
        db_session.add(existing_user)
        await db_session.commit()
        
        user_service = UserService(db_session)
        
        user_data = UserCreate(
            email="existing@example.com",  # Same email
            name="Another User",
            password="SecurePassword123!"
        )
        
        with pytest.raises(ValueError, match="User with this email already exists"):
            await user_service.create_user(user_data)
    
    @pytest.mark.asyncio
    async def test_update_user_profile(self, db_session: AsyncSession):
        """Test user profile update."""
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        user_service = UserService(db_session)
        
        update_data = UserUpdate(
            name="Updated Name",
            email="updated@example.com"
        )
        
        updated_user = await user_service.update_user(
            user.id, 
            update_data, 
            str(user.id)
        )
        
        assert updated_user.name == "Updated Name"
        assert updated_user.email == "updated@example.com"
    
    @pytest.mark.asyncio
    async def test_deactivate_user(self, db_session: AsyncSession):
        """Test user deactivation."""
        user = UserFactory(is_active=True)
        db_session.add(user)
        await db_session.commit()
        
        user_service = UserService(db_session)
        
        deactivated_user = await user_service.deactivate_user(
            user.id, 
            str(user.id)
        )
        
        assert deactivated_user.is_active is False
    
    @pytest.mark.asyncio
    async def test_list_users_with_pagination(self, db_session: AsyncSession):
        """Test user listing with pagination."""
        # Create multiple users
        users = UserFactory.create_batch_async(15)
        for user in users:
            db_session.add(user)
        await db_session.commit()
        
        user_service = UserService(db_session)
        
        # Test first page
        result = await user_service.list_users(
            page=1, 
            size=10, 
            search=None, 
            current_user_id="admin"
        )
        
        assert len(result.users) == 10
        assert result.total >= 15
        assert result.page == 1
        assert result.has_next is True
        
        # Test second page
        result_page2 = await user_service.list_users(
            page=2, 
            size=10, 
            search=None, 
            current_user_id="admin"
        )
        
        assert len(result_page2.users) >= 5
        assert result_page2.page == 2
```

## 🔒 Security Testing

```python
# tests/test_security.py
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import AsyncSession

from tests.factories.user_factory import UserFactory
from tests.factories.auth_factory import TokenFactory

class TestSecurityVulnerabilities:
    """Test common security vulnerabilities."""
    
    def test_sql_injection_protection(self, client: TestClient):
        """Test protection against SQL injection."""
        malicious_payload = {
            "email": "user@example.com'; DROP TABLE users; --",
            "password": "password"
        }
        
        response = client.post("/api/v1/auth/login", json=malicious_payload)
        
        # Should not cause server error, just authentication failure
        assert response.status_code in [400, 401, 422]
    
    def test_password_enumeration_protection(self, client: TestClient):
        """Test protection against user enumeration via timing attacks."""
        import time
        
        # Test with non-existent user
        start_time = time.time()
        response1 = client.post("/api/v1/auth/login", json={
            "email": "nonexistent@example.com",
            "password": "password"
        })
        time1 = time.time() - start_time
        
        # Test with existing user but wrong password
        start_time = time.time()
        response2 = client.post("/api/v1/auth/login", json={
            "email": "admin@example.com",  # Assuming this exists
            "password": "wrongpassword"
        })
        time2 = time.time() - start_time
        
        # Both should return same error and similar timing
        assert response1.status_code == 401
        assert response2.status_code == 401
        assert abs(time1 - time2) < 0.1  # Similar response times
    
    @pytest.mark.asyncio
    async def test_token_tampering_protection(self, client: TestClient, db_session: AsyncSession):
        """Test protection against token tampering."""
        user = UserFactory()
        db_session.add(user)
        await db_session.commit()
        
        # Create valid token and tamper with it
        valid_token = TokenFactory.create_access_token(str(user.id), user.email)
        tampered_token = valid_token[:-10] + "tamperedend"
        
        response = client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        
        assert response.status_code == 401
        assert "Invalid token" in response.json()["detail"].lower()
    
    def test_cors_headers(self, client: TestClient):
        """Test CORS headers are properly configured."""
        response = client.options("/api/v1/auth/login")
        
        # Should include proper CORS headers
        assert "Access-Control-Allow-Origin" in response.headers
        assert "Access-Control-Allow-Methods" in response.headers
        assert "Access-Control-Allow-Headers" in response.headers
    
    def test_rate_limiting_simulation(self, client: TestClient):
        """Test rate limiting behavior (simulated)."""
        # Make multiple rapid requests
        responses = []
        for _ in range(20):
            response = client.post("/api/v1/auth/login", json={
                "email": "test@example.com",
                "password": "wrongpassword"
            })
            responses.append(response.status_code)
        
        # Should have some rate limiting after multiple failed attempts
        # (Implementation depends on your rate limiting strategy)
        assert 429 in responses or all(r == 401 for r in responses)
```

## 📊 Test Coverage and Reporting

### Coverage Configuration

```toml
# pyproject.toml
[tool.coverage.run]
source = ["app"]
omit = [
    "app/main.py",
    "*/migrations/*",
    "*/tests/*",
    "*/__pycache__/*",
]

[tool.coverage.report]
exclude_lines = [
    "pragma: no cover",
    "def __repr__",
    "raise AssertionError",
    "raise NotImplementedError",
    "if __name__ == .__main__.:",
]
```

### Running Tests with Coverage

```bash
# Run all tests with coverage
uv run pytest --cov=app --cov-report=html --cov-report=term-missing

# Run specific test categories
uv run pytest tests/test_auth.py -v
uv run pytest tests/test_rbac.py -v
uv run pytest -k "test_oauth" -v

# Run tests in parallel
uv run pytest -n auto

# Generate detailed coverage report
uv run pytest --cov=app --cov-report=html
open htmlcov/index.html
```

## 🚀 Best Practices

### Test Organization
1. **Group Related Tests**: Use classes to group related test methods
2. **Descriptive Names**: Test names should clearly describe what is being tested
3. **Arrange-Act-Assert**: Structure tests with clear setup, execution, and verification
4. **One Assertion Per Test**: Focus each test on a single behavior

### Factory Usage
1. **Realistic Data**: Factories should generate realistic test data
2. **Minimal Dependencies**: Create only the data needed for each test
3. **Trait Patterns**: Use factory traits for common variations
4. **Cleanup**: Ensure test data doesn't leak between tests

### Async Testing
1. **Proper Fixtures**: Use async fixtures for database operations
2. **Event Loop Management**: Configure event loops correctly
3. **Session Isolation**: Each test should use a fresh database session
4. **Resource Cleanup**: Properly clean up async resources

### Security Testing
1. **Common Vulnerabilities**: Test for OWASP Top 10 vulnerabilities
2. **Input Validation**: Test boundary conditions and invalid inputs
3. **Authentication Bypass**: Test unauthorized access attempts
4. **Data Exposure**: Verify sensitive data is properly protected

### Performance Testing
1. **Database Queries**: Monitor N+1 query problems
2. **Response Times**: Set reasonable response time expectations
3. **Memory Usage**: Check for memory leaks in long-running tests
4. **Concurrency**: Test behavior under concurrent access

## 🔗 Next Steps

- **[Features & API](features-api.md)** - Learn about the OAuth2 capabilities being tested
- **[Project Structure](project-structure.md)** - Understand the codebase being tested
- **[Logging System](logging.md)** - Review logging for test troubleshooting
- **[Deployment](deployment.md)** - Deploy tested code to production 