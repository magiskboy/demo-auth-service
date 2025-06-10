# OAuth2 Service

## Refs:
- [https://github.com/magiskboy/oauth2-impl](https://github.com/magiskboy/oauth2-impl)
- [https://www.nkthanh.dev/posts/oauth2](https://www.nkthanh.dev/posts/oauth2)

A production-ready OAuth2 and OpenID Connect authentication service built with FastAPI, featuring comprehensive logging, RBAC (Role-Based Access Control), and microservice architecture.

## Features

- **OAuth2 & OpenID Connect**: Full OAuth2 implementation with OpenID Connect support
- **Single Sign-On (SSO)**: Seamless authentication across multiple applications
- **Role-Based Access Control (RBAC)**: Comprehensive permission and role management
- **Production Logging**: Structured JSON logging with security filtering and audit trails
- **Microservice Ready**: Containerized architecture for Kubernetes deployment
- **Type Safety**: Full type annotations and validation with Pydantic
- **Comprehensive Testing**: Factory-based testing with pytest and async support

## Documentation

Our documentation is organized into focused sections:

### Core Documentation
- **[Features & API](docs/features-api.md)** - OAuth2, OpenID Connect, SSO capabilities and API reference
- **[Project Structure](docs/project-structure.md)** - Architecture, modules, and code organization
- **[Logging System](docs/logging.md)** - Comprehensive logging setup and usage
- **[Testing Guide](docs/testing.md)** - Testing strategies, best practices, and examples
- **[Deployment](docs/deployment.md)** - Container deployment and Kubernetes orchestration


## Quick Start

```bash
# Clone the repository
git clone <repository-url>
cd oauth2-service

# Install dependencies
uv sync

# Set up environment
cp .env.example .env
# Edit .env with your configuration

# Run the service
uv run uvicorn app.main:app --reload

# Run tests
uv run pytest

# View logs
tail -f logs/oauth2-service-rotating.log | jq
```


## Docker

```bash
# Build container
docker build -t oauth2-service .

# Run with Docker Compose
docker-compose up -d
```
