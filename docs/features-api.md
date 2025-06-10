# Features & API Reference

## Overview

The OAuth2 Service provides a comprehensive authentication and authorization platform with modern security features, SSO capabilities, and a robust API for integration.

## 🔑 Core Features

### OAuth2 & OpenID Connect
- **Full OAuth2 Implementation**: Complete OAuth2 server with authorization code, client credentials, and refresh token flows
- **OpenID Connect**: Standards-compliant OpenID Connect implementation for identity federation
- **JWT Tokens**: Secure access and refresh tokens with configurable expiration times
- **Token Revocation**: Redis-based token blacklisting for secure logout

### Single Sign-On (SSO)
- **Multi-Provider Support**: Extensible SSO with support for multiple identity providers
- **Google OAuth2**: Production-ready Google OAuth2 integration
- **Account Linking**: Link multiple OAuth providers to a single user account
- **Seamless Integration**: Easy integration with existing applications

### Role-Based Access Control (RBAC)
- **Granular Permissions**: Fine-grained permissions for API endpoints
- **Role Management**: Flexible role creation and assignment
- **Dynamic Authorization**: Runtime permission checking for secure access control
- **Audit Trail**: Complete logging of RBAC operations for compliance

### Security Features
- **Password Security**: BCrypt hashing with salt for secure password storage
- **Token Security**: Secure token generation, validation, and revocation
- **Input Validation**: Comprehensive request/response validation with Pydantic
- **Session Management**: Secure session handling with middleware

## 🌐 OAuth2 Flow

![OAuth2 Flow](flow.png)

### Authorization Code Flow

1. **Authorization Request**: Client redirects user to `/auth/login/google`
2. **User Authentication**: User authenticates with the identity provider
3. **Authorization Grant**: Provider redirects back with authorization code
4. **Token Request**: Service exchanges code for access and refresh tokens
5. **User Creation/Linking**: Create new user or link to existing account
6. **Token Response**: Return JWT tokens to client application

### Token Management
```http
# Request tokens
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}

# Response
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 1800
}
```

## 📡 API Reference

### Authentication Endpoints (`/api/v1/auth`)

#### User Registration
```http
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password",
  "name": "John Doe"
}
```

#### User Login
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

#### Token Refresh
```http
POST /api/v1/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

#### Secure Logout
```http
POST /api/v1/auth/logout
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Current User Info
```http
GET /api/v1/auth/me
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Token Verification
```http
POST /api/v1/auth/verify-token
Content-Type: application/json

{
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
}
```

### SSO Endpoints

#### Google OAuth2 Login
```http
GET /api/v1/auth/login/google
# Redirects to Google OAuth2 authorization URL
```

#### Google OAuth2 Callback
```http
GET /api/v1/auth/callback/google?code=authorization_code&state=random_state
# Handles OAuth2 callback and returns tokens
```

### User Management (`/api/v1/users`)

#### Get User Profile
```http
GET /api/v1/users/{user_id}
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Update User Profile
```http
PUT /api/v1/users/{user_id}
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "name": "Updated Name",
  "email": "updated@example.com"
}
```

#### List Users (Admin)
```http
GET /api/v1/users?page=1&size=10&search=john
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

### RBAC Management (`/api/v1/admin`)

#### Role Management

**Create Role**
```http
POST /api/v1/admin/roles
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "name": "admin",
  "description": "Administrator role"
}
```

**List Roles**
```http
GET /api/v1/admin/roles?name=admin
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

**Update Role**
```http
PUT /api/v1/admin/roles/{role_id}
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "name": "super_admin",
  "description": "Super administrator role"
}
```

#### Permission Management

**Create Permission**
```http
POST /api/v1/admin/permissions
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "name": "GET:/api/v1/users",
  "description": "Read users permission"
}
```

**List Permissions**
```http
GET /api/v1/admin/permissions?name=GET:/api/v1/users
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
```

#### Role Assignment

**Assign Role to User**
```http
POST /api/v1/admin/users/{user_id}/roles
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "role_id": "role-uuid-here"
}
```

**Assign Permission to Role**
```http
POST /api/v1/admin/roles/{role_id}/permissions
Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
Content-Type: application/json

{
  "permission_id": "permission-uuid-here"
}
```

## 🔧 Configuration

### OAuth2 Providers
Configure OAuth2 providers in `app/auth/sso_config.py`:

```python
OAUTH_PROVIDERS = {
    'google': {
        'client_id': 'your-google-client-id',
        'client_secret': 'your-google-client-secret',
        'server_metadata_url': 'https://accounts.google.com/.well-known/openid-configuration',
        'client_kwargs': {
            'scope': 'openid email profile'
        }
    }
}
```

### Token Configuration
```python
# Token expiration times
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
REFRESH_TOKEN_EXPIRE_MINUTES = 10080  # 7 days

# JWT signing
SECRET_KEY = "your-secret-key-here"
ALGORITHM = "HS256"
```

### Permission Format
Permissions follow the pattern: `{HTTP_METHOD}:{API_PATH}`

Examples:
- `GET:/api/v1/users` - Read users
- `POST:/api/v1/users` - Create users  
- `PUT:/api/v1/users/{id}` - Update specific user
- `DELETE:/api/v1/admin/roles` - Delete roles (admin)

## 🛡️ Security Considerations

### Token Security
- **Short-lived Access Tokens**: Default 30-minute expiration
- **Refresh Token Rotation**: Refresh tokens expire after 7 days
- **Token Blacklisting**: Redis-based revocation for immediate logout
- **Secure Storage**: Use secure, httpOnly cookies in production

### Password Security
- **BCrypt Hashing**: Industry-standard password hashing
- **Salt Generation**: Automatic salt generation for each password
- **Password Policies**: Configurable password strength requirements

### API Security
- **HTTPS Only**: Force HTTPS in production environments
- **CORS Configuration**: Proper CORS setup for web applications
- **Rate Limiting**: Implement rate limiting for API endpoints
- **Input Validation**: Comprehensive request validation with Pydantic

### RBAC Security
- **Principle of Least Privilege**: Grant minimal required permissions
- **Regular Audits**: Monitor and audit role assignments
- **Permission Hierarchy**: Implement hierarchical permission models
- **Audit Logging**: Complete audit trail for all RBAC operations

## 📊 Data Models

### User Model
```python
class User(OAuthBaseModel, table=True):
    __tablename__ = "users"
    
    email: str = Field(unique=True, index=True)
    name: str
    hashed_password: Optional[str] = Field(default=None)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRole)
```

### Role Model
```python
class Role(OAuthBaseModel, table=True):
    __tablename__ = "roles"
    
    name: str = Field(unique=True)
    description: str = Field(default="")
    users: List["User"] = Relationship(back_populates="roles", link_model=UserRole)
    permissions: List["Permission"] = Relationship(back_populates="roles", link_model=RolePermission)
```

### Permission Model
```python
class Permission(OAuthBaseModel, table=True):
    __tablename__ = "permissions"
    
    name: str = Field(unique=True, description="Format: 'HTTP_METHOD:/path'")
    description: str = Field(default="")
    roles: List["Role"] = Relationship(back_populates="permissions", link_model=RolePermission)
```

## 🔄 Integration Examples

### Client Application Integration
```javascript
// Frontend integration example
const authService = {
  async login(email, password) {
    const response = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    
    return data;
  },
  
  async refreshToken() {
    const refreshToken = localStorage.getItem('refresh_token');
    const response = await fetch('/api/v1/auth/refresh', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
    });
    
    const data = await response.json();
    localStorage.setItem('access_token', data.access_token);
    
    return data;
  }
};
```

### Microservice Integration
```python
# Service-to-service authentication
import httpx

class ServiceClient:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
    
    async def authenticate(self):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                f"{self.base_url}/api/v1/auth/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                }
            )
            data = response.json()
            self.access_token = data["access_token"]
    
    async def make_request(self, method: str, path: str, **kwargs):
        if not self.access_token:
            await self.authenticate()
        
        headers = kwargs.get("headers", {})
        headers["Authorization"] = f"Bearer {self.access_token}"
        kwargs["headers"] = headers
        
        async with httpx.AsyncClient() as client:
            return await client.request(method, f"{self.base_url}{path}", **kwargs)
```

## 📈 Monitoring & Analytics

### API Metrics
The service provides comprehensive metrics for monitoring:

- **Authentication Success/Failure Rates**
- **Token Usage Statistics**
- **API Endpoint Performance**
- **User Registration Trends**
- **OAuth Provider Statistics**

### Health Checks
```http
GET /health
# Returns service health status

GET /metrics
# Returns Prometheus-compatible metrics
```

## 🔗 Next Steps

- **[Project Structure](project-structure.md)** - Learn about the codebase organization
- **[Logging System](logging.md)** - Understand the comprehensive logging features
- **[Testing Guide](testing.md)** - Best practices for testing OAuth2 applications
- **[Deployment](deployment.md)** - Deploy the service in production environments 