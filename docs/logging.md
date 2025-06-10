# Logging System Documentation

## Overview

The OAuth2 service includes a comprehensive logging system designed for production use with features like:

- **Structured JSON logging** for easy parsing and analysis
- **Security-aware filtering** to mask sensitive information
- **Request context tracking** with request IDs and user IDs
- **Multiple output formats** (JSON and text)
- **Environment-based configuration**
- **File rotation** to manage disk space
- **Integration with FastAPI/uvicorn**

## Quick Start

```python
from app.core.logging import setup_logging, get_logger

# Setup logging (usually done at application startup)
setup_logging()

# Get a logger for your module
logger = get_logger(__name__)

# Log messages with structured data
logger.info(
    "User created successfully",
    extra={
        'user_id': 'user-123',
        'email': 'user@example.com',
        'action': 'user_creation'
    }
)
```

## Configuration

The logging system is configured via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LOG_LEVEL` | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `LOG_FORMAT` | `json` | Output format (`json` or `text`) |
| `ENVIRONMENT` | `development` | Environment name (appears in logs) |
| `APP_VERSION` | `1.0.0` | Application version (appears in logs) |

### Examples

```bash
# Debug logging with text format
export LOG_LEVEL=DEBUG
export LOG_FORMAT=text

# Production setup with JSON logging
export LOG_LEVEL=INFO
export LOG_FORMAT=json
export ENVIRONMENT=production
export APP_VERSION=2.1.0
```

## Log Output

### JSON Format (Default)
```json
{
  "timestamp": "2025-06-10T05:15:40.129002",
  "level": "INFO",
  "name": "app.users",
  "message": "User created successfully",
  "service": "oauth2-service",
  "version": "1.0.0",
  "environment": "development",
  "request_id": "req-123",
  "user_id": "user-456",
  "action": "user_creation"
}
```

### Text Format
```
[2025-06-10 12:15:40] [INFO] [app.users] [create_user:45] - User created successfully
```

## Security Features

The logging system automatically masks sensitive information:

```python
logger.info("Login attempt with password: secret123")
# Output: "Login attempt with password=***MASKED***: secret=***MASKED***123"

logger.info("Token: bearer abc123", extra={'api_key': 'sk-123'})
# Sensitive fields in extra data are preserved but marked as sensitive
```

Masked fields include:
- `password`, `secret`, `token`, `key`
- `authorization`, `api_key`, `client_secret`
- `refresh_token`, `access_token`, `csrf_token`

## Request Context

Track requests across your application:

```python
from app.core.logging import LogContext, log_api_request, log_api_response

# Log API request
request_id = str(uuid4())
log_api_request(request_id, 'POST', '/api/v1/users', user_id='user-123')

# Add context to all logs within the block
with LogContext(request_id=request_id, user_id='user-123'):
    logger.info("Processing request")
    logger.info("Validating data")
    
# Log API response
log_api_response(request_id, 201, 150.5, user_id='user-123')
```

## Specialized Loggers

### Authentication Events
```python
from app.core.logging import log_auth_event

log_auth_event(
    'login_success',
    user_id='user-123',
    email='user@example.com',
    ip_address='192.168.1.100'
)

log_auth_event(
    'oauth_login',
    user_id='user-123',
    provider='google',
    sub='google-456789'
)
```

### Security Events
```python
from app.core.logging import log_security_event

log_security_event(
    'suspicious_activity',
    user_id='user-123',
    details='Multiple failed login attempts',
    ip_address='10.0.0.1',
    attempt_count=5
)

log_security_event(
    'rate_limit_exceeded',
    ip_address='192.168.1.100',
    endpoint='/api/v1/auth/login',
    limit=100
)
```

## Class Integration

Use the `LoggerMixin` for easy integration:

```python
from app.core.logging import LoggerMixin

class UserService(LoggerMixin):
    def create_user(self, user_data):
        self.logger.info("Creating user", extra={'email': user_data.email})
        # ... implementation
        self.logger.info("User created successfully", extra={'user_id': user.id})
```

## Function Decorators

Log function calls automatically:

```python
from app.core.logging import log_function_call

@log_function_call
def process_payment(amount, currency):
    # Function calls and results are automatically logged
    return {"status": "success", "amount": amount}
```

## Log Files

The system creates several log files in the `logs/` directory:

| File | Purpose |
|------|---------|
| `oauth2-service-rotating.log` | Main application logs (rotated at 10MB) |
| `oauth2-service.log` | Simple file handler logs |

### File Rotation

- **Max file size**: 10MB
- **Backup count**: 5 files
- **Encoding**: UTF-8
- **Format**: JSON (configurable)

## Integration with FastAPI

The logging system is designed to integrate seamlessly with FastAPI applications:

```python
from fastapi import FastAPI
from app.core.logging import setup_logging

# Setup logging at application startup
setup_logging()

app = FastAPI()

@app.middleware("http")
async def logging_middleware(request, call_next):
    request_id = str(uuid4())
    
    # Log request
    log_api_request(request_id, request.method, str(request.url))
    
    # Process request
    start_time = time.time()
    response = await call_next(request)
    duration = (time.time() - start_time) * 1000
    
    # Log response
    log_api_response(request_id, response.status_code, duration)
    
    return response
```

## Performance Considerations

1. **JSON vs Text**: JSON format has slightly more overhead but provides better structured data
2. **Log Level**: Use INFO or higher in production; DEBUG generates many log entries
3. **File Rotation**: Automatic rotation prevents disk space issues
4. **Async Logging**: The system uses synchronous logging; consider async handlers for high-throughput scenarios

## Best Practices

1. **Use structured logging**: Include relevant context in `extra` parameters
2. **Don't log sensitive data**: The security filter helps, but be mindful of what you log
3. **Use appropriate log levels**:
   - `DEBUG`: Detailed diagnostic information
   - `INFO`: General information about application flow
   - `WARNING`: Something unexpected happened but application continues
   - `ERROR`: Error occurred, might impact functionality
   - `CRITICAL`: Serious error, application might stop

4. **Include context**: Use request IDs and user IDs for traceability
5. **Log business events**: Track important business operations for auditing

## Example Usage

See `examples/logging_demo.py` for a comprehensive demonstration of all logging features.

Run the demo:
```bash
python examples/logging_demo.py
```

Or with custom configuration:
```bash
LOG_LEVEL=DEBUG LOG_FORMAT=text python examples/logging_demo.py
```

## Troubleshooting

### Common Issues

1. **Logs not appearing**: Check `LOG_LEVEL` environment variable
2. **Missing log files**: Ensure the application has write permissions to the `logs/` directory
3. **Performance issues**: Consider raising the log level or using async logging for high-volume applications

### Debug Tips

```python
# Check current logging configuration
import logging
print(logging.getLogger().handlers)
print(logging.getLogger().level)

# Test logging levels
logger = get_logger('test')
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message")
``` 