# Project Structure

## Overview

The OAuth2 Service follows a **feature-based modular architecture** similar to Django's app structure, emphasizing separation of concerns, type safety, and maintainability. Each module encapsulates related functionality with clear boundaries and well-defined interfaces.

## Architecture Principles

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