# 🔐 Basic Authentication Guide

## Tổng quan

Project hiện đã hỗ trợ **HTTP Basic Authentication** bên cạnh Bearer token authentication và OAuth2 Google. Basic Authentication sử dụng email/password được encode trong header `Authorization`.

## 🚀 Các tính năng Basic Authentication

### 1. **Basic Authentication Dependencies**

```python
from app.auth.security import (
    get_current_user_basic,           # Basic auth user
    get_current_active_user_basic,    # Active user only
    get_current_verified_user_basic,  # Verified user only
    get_current_user_flexible         # Bearer OR Basic
)
```

### 2. **Endpoint Examples**

#### Chỉ Basic Auth:
```python
@router.get("/basic/profile")
async def basic_profile(user: User = Depends(get_current_user_basic)):
    return {"message": f"Hello {user.name}"}
```

#### Flexible Auth (Bearer OR Basic):
```python
@router.get("/flexible/dashboard")
async def dashboard(user: User = Depends(get_current_user_flexible)):
    return {"message": f"Welcome {user.name}"}
```

## 📝 Cách sử dụng

### 1. **Tạo Basic Auth Header**

```bash
# Format: username:password -> base64
echo -n "user@example.com:password123" | base64
# Output: dXNlckBleGFtcGxlLmNvbTpwYXNzd29yZDEyMw==
```

### 2. **Test với cURL**

```bash
# Basic Authentication
curl -X GET "http://localhost:8000/api/v1/auth/basic/me" \
     -H "Authorization: Basic dXNlckBleGFtcGxlLmNvbTpwYXNzd29yZDEyMw=="

# Flexible Authentication (Basic)
curl -X GET "http://localhost:8000/api/v1/auth/flexible/me" \
     -H "Authorization: Basic dXNlckBleGFtcGxlLmNvbTpwYXNzd29yZDEyMw=="

# Flexible Authentication (Bearer)
curl -X GET "http://localhost:8000/api/v1/auth/flexible/me" \
     -H "Authorization: Bearer your_jwt_token_here"
```

### 3. **Test với Python requests**

```python
import requests
import base64

# Prepare credentials
email = "user@example.com"
password = "password123"
credentials = base64.b64encode(f"{email}:{password}".encode()).decode()

# Basic Auth request
response = requests.get(
    "http://localhost:8000/api/v1/auth/basic/me",
    headers={"Authorization": f"Basic {credentials}"}
)

print(response.json())
```

### 4. **Test với JavaScript/fetch**

```javascript
// Prepare credentials
const email = "user@example.com";
const password = "password123";
const credentials = btoa(`${email}:${password}`);

// Basic Auth request
fetch("http://localhost:8000/api/v1/auth/basic/me", {
    headers: {
        "Authorization": `Basic ${credentials}`
    }
})
.then(response => response.json())
.then(data => console.log(data));
```

## 🛡️ Security Features

### 1. **User Validation**
- ✅ Email/password verification
- ✅ Active user check
- ✅ Deleted user check
- ✅ Email verification check

### 2. **Error Handling**
```json
{
    "detail": "Invalid authentication credentials",
    "headers": {
        "WWW-Authenticate": "Basic"
    }
}
```

### 3. **Role-based Access**
```python
from app.auth.security import require_roles

@router.get("/admin/users")
@require_roles("admin", "moderator")
async def admin_users(user: User = Depends(get_current_user_basic)):
    return {"users": []}
```

## 📋 Available Endpoints

### Basic Authentication Only:
- `GET /api/v1/auth/basic/me` - User info via Basic Auth
- `GET /api/v1/auth/basic/profile` - User profile (active users)
- `GET /api/v1/auth/basic/verified-only` - Verified users only

### Flexible Authentication (Bearer OR Basic):
- `GET /api/v1/auth/flexible/me` - User info
- `GET /api/v1/auth/flexible/dashboard` - Dashboard

### Bearer Token Only (existing):
- `GET /api/v1/auth/me` - User info via Bearer token
- `POST /api/v1/auth/logout` - Logout

## 🔧 Implementation Details

### 1. **Security Components**
```python
# security.py
basic_security = HTTPBasic()  # FastAPI Basic Auth scheme

async def verify_basic_credentials(
    credentials: HTTPBasicCredentials = Depends(basic_security),
    db: AsyncSession = Depends(get_db)
) -> User:
    # Username = email, Password = plain password
    user = await authenticate_user(credentials.username, credentials.password, db)
    # ... validation logic
```

### 2. **Flexible Authentication Logic**
```python
async def get_current_user_flexible(...):
    # Try Bearer first
    if bearer_credentials:
        try:
            return await get_current_user(bearer_credentials, db)
        except HTTPException:
            pass
    
    # Fallback to Basic
    if basic_credentials:
        return await verify_basic_credentials(basic_credentials, db)
    
    # Neither provided
    raise HTTPException(401, "Provide Bearer token or Basic auth")
```

## 🚀 Production Considerations

### 1. **HTTPS Only**
```python
# Chỉ sử dụng Basic Auth qua HTTPS trong production
if not request.url.scheme == "https":
    raise HTTPException(400, "Basic Auth requires HTTPS")
```

### 2. **Rate Limiting**
```python
# Thêm rate limiting cho Basic Auth endpoints
from slowapi import Limiter

@limiter.limit("10/minute")
async def basic_auth_endpoint(...):
    pass
```

### 3. **Logging**
```python
import logging

logger = logging.getLogger(__name__)

async def verify_basic_credentials(...):
    logger.info(f"Basic auth attempt for: {credentials.username}")
    # ... auth logic
```

## 🧪 Testing

```bash
# Start server
uvicorn asgi:app --reload

# Test Basic Auth
curl -u "user@example.com:password123" \
     http://localhost:8000/api/v1/auth/basic/me

# Test Flexible Auth with Basic
curl -u "user@example.com:password123" \
     http://localhost:8000/api/v1/auth/flexible/dashboard

# Test Flexible Auth with Bearer
curl -H "Authorization: Bearer <jwt_token>" \
     http://localhost:8000/api/v1/auth/flexible/dashboard
```

## 📊 Comparison

| Feature | Bearer Token | Basic Auth | Flexible |
|---------|-------------|------------|----------|
| Stateless | ✅ | ✅ | ✅ |
| Expiration | ✅ (JWT exp) | ❌ | ✅/❌ |
| Security | 🔒🔒🔒 | 🔒🔒 | 🔒🔒🔒 |
| Microservices | ✅ | ✅ | ✅ |
| Mobile Apps | ✅ | ✅ | ✅ |
| Browser Support | ✅ | ✅ | ✅ |

**Khuyến nghị:** Sử dụng Bearer token cho user apps, Basic Auth cho service-to-service, và Flexible cho backward compatibility. 