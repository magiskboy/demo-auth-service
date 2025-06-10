# Project Structure

## Overview

The OAuth2 Service follows a **feature-based modular architecture** similar to Django's app structure, emphasizing separation of concerns, type safety, and maintainability. Each module encapsulates related functionality with clear boundaries and well-defined interfaces.

## 🏗️ Architecture Principles

### Feature-Based Organization
- **Modular Design**: Each feature is contained in its own module
- **Clear Boundaries**: Modules have well-defined interfaces and responsibilities
- **Loose Coupling**: Modules communicate through defined contracts
- **High Cohesion**: Related functionality is grouped together

### Type Safety & Modern Python
- **Full Type Annotations**: Every function, class, and variable is type-annotated
- **Pydantic Models**: Runtime validation with type checking
- **SQLModel Integration**: Type-safe database operations
- **MyPy Compatibility**: Static type checking support

## 📁 Directory Structure

```
oauth2-service/
├── app/                        # Main application package
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   │
│   ├── core/                   # Core functionality & infrastructure
│   │   ├── __init__.py
│   │   ├── config.py           # Configuration management
│   │   ├── database.py         # Database connection & session management
│   │   ├── redis.py            # Redis connection & utilities
│   │   ├── logging.py          # Comprehensive logging system
│   │   ├── dependencies.py     # FastAPI dependency injection
│   │   └── exceptions.py       # Custom exception classes
│   │
│   ├── auth/                   # Authentication & OAuth2 logic
│   │   ├── __init__.py
│   │   ├── router.py           # API endpoints for authentication
│   │   ├── services.py         # Business logic for auth operations
│   │   ├── schemas.py          # Pydantic models for request/response
│   │   ├── models.py           # Database models for auth
│   │   ├── dependencies.py     # Auth-specific dependencies
│   │   ├── oauth2.py           # OAuth2 token handling
│   │   ├── sso_config.py       # SSO provider configurations
│   │   └── utils.py            # Auth utility functions
│   │
│   ├── users/                  # User management
│   │   ├── __init__.py
│   │   ├── router.py           # User-related API endpoints
│   │   ├── services.py         # User business logic
│   │   ├── schemas.py          # User Pydantic models
│   │   ├── models.py           # User database models
│   │   └── dependencies.py     # User-specific dependencies
│   │
│   ├── rbac/                   # Role-Based Access Control
│   │   ├── __init__.py
│   │   ├── services.py         # RBAC business logic
│   │   ├── schemas.py          # RBAC Pydantic models
│   │   ├── models.py           # Role, Permission database models
│   │   └── middleware.py       # Permission checking middleware
│   │
│   └── admin/                  # Administrative functions
│       ├── __init__.py
│       ├── router.py           # Admin API endpoints
│       ├── services.py         # Admin business logic
│       └── schemas.py          # Admin Pydantic models
│
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── conftest.py             # Pytest configuration & fixtures
│   ├── factories/              # Test data factories
│   │   ├── __init__.py
│   │   ├── user_factory.py     # User test data generation
│   │   ├── role_factory.py     # Role test data generation
│   │   └── auth_factory.py     # Auth test data generation
│   │
│   ├── test_auth.py            # Authentication tests
│   ├── test_users.py           # User management tests
│   ├── test_rbac.py            # RBAC functionality tests
│   └── test_admin.py           # Admin functionality tests
│
├── examples/                   # Example scripts & demos
│   ├── logging_demo.py         # Logging system demonstration
│   ├── rbac_logging_demo.py    # RBAC logging demonstration
│   └── fastapi_logging_integration.py  # FastAPI logging integration
│
├── docs/                       # Documentation
│   ├── features-api.md         # Features & API documentation
│   ├── project-structure.md    # This file
│   ├── logging.md              # Logging documentation
│   ├── logging-vi.md           # Vietnamese logging docs
│   ├── testing.md              # Testing documentation
│   ├── deployment.md           # Deployment documentation
│   └── flow.png                # OAuth2 flow diagram
│
├── k8s/                        # Kubernetes manifests
│   ├── deployment.yaml         # Application deployment
│   ├── service.yaml            # Kubernetes service
│   ├── configmap.yaml          # Configuration
│   └── ingress.yaml            # Ingress configuration
│
├── logs/                       # Log files (created at runtime)
│   ├── oauth2-service.log      # Main log file
│   └── oauth2-service-rotating.log  # Rotating log file
│
├── .env.example                # Environment variables template
├── .gitignore                  # Git ignore rules
├── docker-compose.yml          # Docker Compose configuration
├── Dockerfile                  # Container build instructions
├── pyproject.toml              # Project configuration & dependencies
├── README.md                   # Main project documentation
└── uv.lock                     # Dependency lock file
```

## 🎯 Module Architecture

### Core Module (`app/core/`)

The core module provides infrastructure and shared functionality:

```python
# app/core/config.py
from pydantic_settings import BaseSettings
from typing import Optional

class Settings(BaseSettings):
    """Application configuration with type safety."""
    database_url: str
    redis_url: str = "redis://localhost:6379"
    secret_key: str
    log_level: str = "INFO"
    environment: str = "development"
    
    class Config:
        env_file = ".env"

settings = Settings()
```

```python
# app/core/database.py
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from sqlmodel import SQLModel
from typing import AsyncGenerator

class DatabaseManager:
    """Type-safe database connection management."""
    
    def __init__(self, database_url: str):
        self.engine = create_async_engine(database_url)
        self.session_factory = sessionmaker(
            self.engine, 
            class_=AsyncSession, 
            expire_on_commit=False
        )
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        async with self.session_factory() as session:
            yield session
```

### Feature Modules Structure

Each feature module follows a consistent pattern:

#### 1. Models (`models.py`)
```python
# app/users/models.py
from sqlmodel import SQLModel, Field, Relationship
from typing import Optional, List
from uuid import UUID, uuid4
from datetime import datetime

class User(SQLModel, table=True):
    """User database model with full type annotations."""
    __tablename__ = "users"
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True, max_length=255)
    name: str = Field(max_length=100)
    hashed_password: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Relationships with type annotations
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRole)
    linked_accounts: List["LinkedAccount"] = Relationship(back_populates="user")
```

#### 2. Schemas (`schemas.py`)
```python
# app/users/schemas.py
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List
from uuid import UUID
from datetime import datetime

class UserBase(BaseModel):
    """Base user schema with common fields."""
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)

class UserCreate(UserBase):
    """Schema for user creation with validation."""
    password: str = Field(min_length=8, max_length=100)

class UserUpdate(BaseModel):
    """Schema for user updates with optional fields."""
    email: Optional[EmailStr] = None
    name: Optional[str] = Field(None, min_length=1, max_length=100)
    is_active: Optional[bool] = None

class UserResponse(UserBase):
    """Schema for user responses."""
    id: UUID
    is_active: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class UserListResponse(BaseModel):
    """Paginated user list response."""
    users: List[UserResponse]
    total: int
    page: int
    size: int
    has_next: bool
```

#### 3. Services (`services.py`)
```python
# app/users/services.py
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from typing import Optional, List
from uuid import UUID

from app.core.logging import LoggerMixin, log_security_event
from .models import User
from .schemas import UserCreate, UserUpdate, UserListResponse

class UserService(LoggerMixin):
    """User business logic with comprehensive logging."""
    
    def __init__(self, db: AsyncSession):
        self.db = db
        self.logger.info("UserService initialized")
    
    async def create_user(self, user_data: UserCreate) -> User:
        """Create a new user with validation and logging."""
        self.logger.info(
            "Creating new user",
            extra={"email": user_data.email, "action": "user_creation"}
        )
        
        # Check if user already exists
        existing_user = await self.get_user_by_email(user_data.email)
        if existing_user:
            self.logger.warning(
                "User creation failed - email already exists",
                extra={"email": user_data.email}
            )
            raise ValueError("User with this email already exists")
        
        # Create user
        user = User(
            email=user_data.email,
            name=user_data.name,
            hashed_password=hash_password(user_data.password)
        )
        
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        
        # Log security event
        log_security_event(
            "user_created",
            user_id=str(user.id),
            email=user.email,
            details="New user account created"
        )
        
        self.logger.info(
            "User created successfully",
            extra={"user_id": str(user.id), "email": user.email}
        )
        
        return user
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve user by email with logging."""
        statement = select(User).where(User.email == email)
        result = await self.db.exec(statement)
        user = result.first()
        
        if user:
            self.logger.debug(
                "User found by email",
                extra={"user_id": str(user.id), "email": email}
            )
        else:
            self.logger.debug(
                "User not found by email",
                extra={"email": email}
            )
        
        return user
```

#### 4. Routers (`router.py`)
```python
# app/users/router.py
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List
from uuid import UUID

from app.core.database import get_db_session
from app.core.logging import log_api_request, log_api_response
from app.auth.dependencies import get_current_user
from .services import UserService
from .schemas import UserResponse, UserUpdate, UserListResponse
from .models import User

router = APIRouter(prefix="/api/v1/users", tags=["users"])

@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """Get current user's profile."""
    log_api_request("get_user_profile", "GET", "/api/v1/users/me", str(current_user.id))
    
    response = UserResponse.from_orm(current_user)
    
    log_api_response("get_user_profile", 200, user_id=str(current_user.id))
    return response

@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: UUID,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
) -> UserResponse:
    """Update user profile with permission checking."""
    log_api_request("update_user", "PUT", f"/api/v1/users/{user_id}", str(current_user.id))
    
    # Permission check
    if current_user.id != user_id and not await has_permission(current_user, "PUT:/api/v1/users"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions"
        )
    
    user_service = UserService(db)
    updated_user = await user_service.update_user(user_id, user_update, str(current_user.id))
    
    log_api_response("update_user", 200, user_id=str(current_user.id))
    return UserResponse.from_orm(updated_user)

@router.get("", response_model=UserListResponse)
async def list_users(
    page: int = Query(1, ge=1),
    size: int = Query(10, ge=1, le=100),
    search: str = Query(None),
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user)
) -> UserListResponse:
    """List users with pagination and search."""
    log_api_request("list_users", "GET", "/api/v1/users", str(current_user.id))
    
    user_service = UserService(db)
    result = await user_service.list_users(page, size, search, str(current_user.id))
    
    log_api_response("list_users", 200, user_id=str(current_user.id))
    return result
```

#### 5. Dependencies (`dependencies.py`)
```python
# app/users/dependencies.py
from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

from app.core.database import get_db_session
from app.core.logging import get_logger
from .services import UserService
from .models import User

logger = get_logger(__name__)

async def get_user_service(db: AsyncSession = Depends(get_db_session)) -> UserService:
    """Dependency to get UserService instance."""
    return UserService(db)

async def get_user_by_id(
    user_id: UUID,
    user_service: UserService = Depends(get_user_service)
) -> User:
    """Dependency to get user by ID with error handling."""
    user = await user_service.get_user_by_id(user_id)
    if not user:
        logger.warning(f"User not found: {user_id}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user
```

## 🔒 Type Safety Implementation

### Full Type Annotations
Every component uses comprehensive type annotations:

```python
from typing import Optional, List, Dict, Any, Union, Callable, AsyncGenerator
from uuid import UUID
from datetime import datetime
from sqlalchemy.ext.asyncio import AsyncSession

# Function signatures with full type annotations
async def create_user(
    user_data: UserCreate,
    db: AsyncSession,
    current_user_id: Optional[UUID] = None
) -> User:
    """Create user with complete type safety."""
    pass

# Class attributes with type annotations
class AuthService:
    db: AsyncSession
    redis_client: Redis
    logger: Logger
    
    def __init__(self, db: AsyncSession, redis_client: Redis) -> None:
        self.db = db
        self.redis_client = redis_client
        self.logger = get_logger(__name__)
```

### Pydantic Model Validation
Runtime validation with comprehensive error handling:

```python
from pydantic import BaseModel, Field, validator, root_validator
from typing import Optional
from datetime import datetime

class UserCreate(BaseModel):
    """User creation with comprehensive validation."""
    email: EmailStr
    name: str = Field(min_length=1, max_length=100)
    password: str = Field(min_length=8)
    
    @validator('password')
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain digit')
        return v
    
    @validator('name')
    def validate_name(cls, v: str) -> str:
        """Validate name format."""
        if not v.strip():
            raise ValueError('Name cannot be empty')
        return v.strip()
```

### SQLModel Integration
Type-safe database operations:

```python
from sqlmodel import SQLModel, Field, Relationship, select
from typing import Optional, List, TYPE_CHECKING

if TYPE_CHECKING:
    from app.rbac.models import Role

class User(SQLModel, table=True):
    """Type-safe user model."""
    __tablename__ = "users"
    
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    email: str = Field(unique=True, index=True)
    
    # Type-safe relationships
    roles: List["Role"] = Relationship(
        back_populates="users",
        link_model=UserRole
    )

# Type-safe queries
async def get_users_with_roles(db: AsyncSession) -> List[User]:
    """Get users with their roles - fully type-safe."""
    statement = select(User).options(selectinload(User.roles))
    result = await db.exec(statement)
    return result.all()
```

## 🔄 Inter-Module Communication

### Service Layer Pattern
Modules communicate through well-defined service interfaces:

```python
# app/auth/services.py
from app.users.services import UserService
from app.rbac.services import RBACService

class AuthService(LoggerMixin):
    """Authentication service with type-safe dependencies."""
    
    def __init__(
        self,
        db: AsyncSession,
        user_service: UserService,
        rbac_service: RBACService
    ):
        self.db = db
        self.user_service = user_service
        self.rbac_service = rbac_service
    
    async def authenticate_user(
        self,
        email: str,
        password: str
    ) -> Optional[User]:
        """Authenticate user using UserService."""
        user = await self.user_service.get_user_by_email(email)
        if user and verify_password(password, user.hashed_password):
            return user
        return None
    
    async def check_permission(
        self,
        user: User,
        permission: str
    ) -> bool:
        """Check user permission using RBACService."""
        return await self.rbac_service.user_has_permission(user.id, permission)
```

### Dependency Injection
Clean dependency management with FastAPI:

```python
# app/core/dependencies.py
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from typing import AsyncGenerator

from app.core.database import get_db_session
from app.users.services import UserService
from app.rbac.services import RBACService
from app.auth.services import AuthService

async def get_auth_service(
    db: AsyncSession = Depends(get_db_session)
) -> AuthService:
    """Create AuthService with all dependencies."""
    user_service = UserService(db)
    rbac_service = RBACService(db)
    return AuthService(db, user_service, rbac_service)
```

## 🧪 Testing Architecture

### Factory Pattern for Test Data
```python
# tests/factories/user_factory.py
import factory
from faker import Faker
from app.users.models import User

fake = Faker()

class UserFactory(factory.Factory):
    """Type-safe user factory for testing."""
    class Meta:
        model = User
    
    id = factory.LazyFunction(lambda: str(uuid4()))
    email = factory.LazyAttribute(lambda obj: fake.email())
    name = factory.LazyAttribute(lambda obj: fake.name())
    is_active = True
    is_verified = False
    created_at = factory.LazyFunction(datetime.utcnow)
    updated_at = factory.LazyFunction(datetime.utcnow)
```

### Module-Specific Test Structure
```python
# tests/test_users.py
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.users.services import UserService
from app.users.schemas import UserCreate
from tests.factories.user_factory import UserFactory

class TestUserService:
    """Comprehensive user service tests."""
    
    @pytest.mark.asyncio
    async def test_create_user(self, db_session: AsyncSession):
        """Test user creation with type safety."""
        user_service = UserService(db_session)
        user_data = UserCreate(
            email="test@example.com",
            name="Test User",
            password="SecurePass123"
        )
        
        user = await user_service.create_user(user_data)
        
        assert user.email == "test@example.com"
        assert user.name == "Test User"
        assert user.is_active is True
```

## 📦 Package Management

### Modern Python Tooling
```toml
# pyproject.toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "oauth2-service"
version = "1.0.0"
description = "Production OAuth2 service with FastAPI"
dependencies = [
    "fastapi>=0.104.0",
    "sqlmodel>=0.0.14",
    "pydantic>=2.0.0",
    "uvicorn>=0.24.0",
    "asyncpg>=0.29.0",
    "redis>=5.0.0",
    "python-multipart>=0.0.6",
    "python-jose[cryptography]>=3.3.0",
    "passlib[bcrypt]>=1.7.4",
    "authlib>=1.2.1",
]

[project.optional-dependencies]
dev = [
    "pytest>=7.0.0",
    "pytest-asyncio>=0.21.0",
    "pytest-cov>=4.0.0",
    "factory-boy>=3.3.0",
    "faker>=19.0.0",
    "mypy>=1.5.0",
    "black>=23.0.0",
    "isort>=5.12.0",
]

[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_configs = true
disallow_untyped_defs = true
```

## 🎯 Best Practices

### Code Organization
1. **Single Responsibility**: Each module has one clear purpose
2. **Interface Segregation**: Small, focused interfaces
3. **Dependency Inversion**: Depend on abstractions, not concretions
4. **Don't Repeat Yourself**: Common functionality in core module

### Type Safety
1. **Complete Annotations**: All functions and classes are typed
2. **Runtime Validation**: Pydantic models for data validation
3. **Static Analysis**: MyPy integration for type checking
4. **Generic Types**: Use generics for reusable components

### Error Handling
1. **Custom Exceptions**: Domain-specific exception classes
2. **Comprehensive Logging**: All errors are logged with context
3. **Graceful Degradation**: Fallback mechanisms for failures
4. **User-Friendly Messages**: Clear error messages for clients

### Security
1. **Input Validation**: All inputs validated with Pydantic
2. **SQL Injection Prevention**: ORM-based queries only
3. **Authentication Middleware**: Centralized auth checking
4. **Audit Trails**: All security events logged

## 🔗 Next Steps

- **[Features & API](features-api.md)** - Explore the OAuth2 and SSO capabilities
- **[Logging System](logging.md)** - Learn about the comprehensive logging
- **[Testing Guide](testing.md)** - Understand the testing strategies
- **[Deployment](deployment.md)** - Deploy in production environments 