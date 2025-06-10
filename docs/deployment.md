# Deployment Guide

## Overview

The OAuth2 Service is designed as a **cloud-native microservice** optimized for containerized deployment on **Kubernetes**. This guide covers everything from local development to production deployment in orchestrated environments.

## Containerization

### Dockerfile

The service uses a multi-stage build for optimal production images:

```dockerfile
# Build stage
FROM python:3.11-slim as builder

# Set build arguments
ARG BUILDPLATFORM
ARG TARGETPLATFORM

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv package manager
RUN pip install uv

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Install dependencies
RUN uv sync --frozen --no-dev

# Production stage
FROM python:3.11-slim as production

# Create non-root user
RUN groupadd -r oauth2 && useradd -r -g oauth2 oauth2

# Set working directory
WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv

# Copy application code
COPY app/ ./app/
COPY --chown=oauth2:oauth2 . .

# Create logs directory
RUN mkdir -p logs && chown oauth2:oauth2 logs

# Switch to non-root user
USER oauth2

# Set environment variables
ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

### Docker Compose for Development

```yaml
# docker-compose.yml
version: '3.8'

services:
  oauth2-service:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://oauth2_user:oauth2_pass@postgres:5432/oauth2_db
      - REDIS_URL=redis://redis:6379
      - SECRET_KEY=${SECRET_KEY:-development-secret-key}
      - LOG_LEVEL=INFO
      - LOG_FORMAT=json
      - ENVIRONMENT=development
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    volumes:
      - ./logs:/app/logs
    networks:
      - oauth2-network
    restart: unless-stopped

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=oauth2_user
      - POSTGRES_PASSWORD=oauth2_pass
      - POSTGRES_DB=oauth2_db
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./scripts/init-db.sql:/docker-entrypoint-initdb.d/init.sql
    networks:
      - oauth2-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U oauth2_user -d oauth2_db"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - oauth2-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf
      - ./nginx/ssl:/etc/nginx/ssl
    depends_on:
      - oauth2-service
    networks:
      - oauth2-network
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:

networks:
  oauth2-network:
    driver: bridge
```

### Environment Configuration

```bash
# .env.production
DATABASE_URL=postgresql+asyncpg://oauth2_user:secure_password@postgres:5432/oauth2_db
REDIS_URL=redis://redis:6379/0
SECRET_KEY=your-super-secure-secret-key-here
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_MINUTES=10080
LOG_LEVEL=INFO
LOG_FORMAT=json
ENVIRONMENT=production
APP_VERSION=1.0.0

# OAuth2 configuration
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# Security settings
CORS_ORIGINS=["https://your-frontend.com"]
ALLOWED_HOSTS=["oauth2-service.com", "api.oauth2-service.com"]
```

## Next Steps

- **[Features & API](features-api.md)** - Review the capabilities you're deploying
- **[Project Structure](project-structure.md)** - Understand the application architecture
- **[Testing Guide](testing.md)** - Implement comprehensive testing before deployment
- **[Logging System](logging.md)** - Configure monitoring and observability

## Additional Resources

- [Kubernetes Best Practices](https://kubernetes.io/docs/concepts/best-practices/)
- [Docker Security](https://docs.docker.com/engine/security/)
- [Istio Service Mesh](https://istio.io/latest/docs/)
- [Prometheus Monitoring](https://prometheus.io/docs/)
- [ArgoCD GitOps](https://argo-cd.readthedocs.io/) 