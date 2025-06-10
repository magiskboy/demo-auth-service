#!/usr/bin/env python3
"""
FastAPI integration example for the OAuth2 service logging system.

This example shows how to integrate the logging system with a FastAPI application
including middleware for request/response logging and structured logging in endpoints.
"""

import time
from uuid import uuid4
from typing import Optional

from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# Add the parent directory to the path so we can import app modules
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.core.logging import (
    setup_logging,
    get_logger,
    LogContext,
    log_api_request,
    log_api_response,
    log_auth_event,
    log_security_event,
    LoggerMixin
)


# Setup logging
setup_logging()

# Create FastAPI app
app = FastAPI(title="OAuth2 Service Logging Demo", version="1.0.0")


# Pydantic models
class UserCreate(BaseModel):
    email: str
    name: str
    password: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    is_active: bool


class LoginRequest(BaseModel):
    email: str
    password: str


# Service class with logging
class DemoUserService(LoggerMixin):
    """Demo user service with integrated logging."""
    
    def __init__(self):
        self.users = {}  # In-memory storage for demo
        self.logger.info("DemoUserService initialized")
    
    def create_user(self, user_data: UserCreate, request_id: str) -> UserResponse:
        """Create a new user with logging."""
        user_id = str(uuid4())
        
        self.logger.info(
            "Creating new user",
            extra={
                'request_id': request_id,
                'email': user_data.email,
                'operation': 'create_user'
            }
        )
        
        # Simulate validation
        if user_data.email in [u['email'] for u in self.users.values()]:
            self.logger.warning(
                "User creation failed - email already exists",
                extra={
                    'request_id': request_id,
                    'email': user_data.email,
                    'reason': 'duplicate_email'
                }
            )
            raise HTTPException(status_code=400, detail="Email already exists")
        
        # Create user
        user = {
            'id': user_id,
            'email': user_data.email,
            'name': user_data.name,
            'is_active': True
        }
        self.users[user_id] = user
        
        self.logger.info(
            "User created successfully",
            extra={
                'request_id': request_id,
                'user_id': user_id,
                'email': user_data.email
            }
        )
        
        return UserResponse(**user)
    
    def authenticate_user(self, email: str, password: str, request_id: str, client_ip: str) -> Optional[UserResponse]:
        """Authenticate user with security logging."""
        
        # Find user by email
        user = None
        for u in self.users.values():
            if u['email'] == email:
                user = u
                break
        
        if not user:
            log_auth_event(
                'login_failure',
                email=email,
                reason='user_not_found',
                ip_address=client_ip,
                request_id=request_id
            )
            return None
        
        # Simulate password check (always succeeds for demo)
        if password == "correct_password":
            log_auth_event(
                'login_success',
                user_id=user['id'],
                email=email,
                ip_address=client_ip,
                request_id=request_id
            )
            return UserResponse(**user)
        else:
            log_auth_event(
                'login_failure',
                email=email,
                reason='invalid_password',
                ip_address=client_ip,
                request_id=request_id
            )
            
            # Log security event for multiple failures (simulated)
            log_security_event(
                'authentication_failure',
                details='Invalid password attempt',
                ip_address=client_ip,
                email=email
            )
            
            return None


# Create service instance
user_service = DemoUserService()


@app.middleware("http")
async def logging_middleware(request: Request, call_next):
    """Middleware to log all requests and responses."""
    
    # Generate request ID
    request_id = str(uuid4())
    
    # Get client IP
    client_ip = request.client.host
    
    # Log incoming request
    log_api_request(
        request_id=request_id,
        method=request.method,
        path=str(request.url.path),
        user_id=None  # Would be extracted from JWT in real app
    )
    
    # Start timer
    start_time = time.time()
    
    # Add request context
    with LogContext(request_id=request_id, client_ip=client_ip):
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log successful response
            log_api_response(
                request_id=request_id,
                status_code=response.status_code,
                duration_ms=duration_ms,
                user_id=None
            )
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            return response
            
        except Exception as exc:
            # Calculate duration
            duration_ms = (time.time() - start_time) * 1000
            
            # Log error response
            logger = get_logger('app.middleware')
            logger.error(
                "Request processing failed",
                extra={
                    'request_id': request_id,
                    'method': request.method,
                    'path': str(request.url.path),
                    'duration_ms': duration_ms,
                    'error': str(exc),
                    'error_type': type(exc).__name__
                },
                exc_info=True
            )
            
            # Return generic error response
            return JSONResponse(
                status_code=500,
                content={"detail": "Internal server error", "request_id": request_id},
                headers={"X-Request-ID": request_id}
            )


def get_request_id(request: Request) -> str:
    """Dependency to get request ID from context."""
    # In real middleware, this would be stored in request state
    return str(uuid4())


def get_client_ip(request: Request) -> str:
    """Dependency to get client IP."""
    return request.client.host


@app.get("/")
async def root():
    """Root endpoint with basic logging."""
    logger = get_logger('app.endpoints')
    logger.info("Root endpoint accessed")
    return {"message": "OAuth2 Service Logging Demo", "status": "healthy"}


@app.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    request: Request,
    request_id: str = Depends(get_request_id)
):
    """Create a new user with comprehensive logging."""
    logger = get_logger('app.endpoints.users')
    
    logger.info(
        "User creation endpoint called",
        extra={
            'request_id': request_id,
            'email': user_data.email,
            'endpoint': 'create_user'
        }
    )
    
    try:
        user = user_service.create_user(user_data, request_id)
        
        logger.info(
            "User creation endpoint completed successfully",
            extra={
                'request_id': request_id,
                'user_id': user.id,
                'endpoint': 'create_user'
            }
        )
        
        return user
        
    except HTTPException as e:
        logger.warning(
            "User creation endpoint failed with client error",
            extra={
                'request_id': request_id,
                'status_code': e.status_code,
                'detail': e.detail,
                'endpoint': 'create_user'
            }
        )
        raise
        
    except Exception as e:
        logger.error(
            "User creation endpoint failed with server error",
            extra={
                'request_id': request_id,
                'error': str(e),
                'error_type': type(e).__name__,
                'endpoint': 'create_user'
            },
            exc_info=True
        )
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/auth/login")
async def login(
    login_data: LoginRequest,
    request: Request,
    request_id: str = Depends(get_request_id),
    client_ip: str = Depends(get_client_ip)
):
    """Login endpoint with authentication and security logging."""
    logger = get_logger('app.endpoints.auth')
    
    logger.info(
        "Login endpoint called",
        extra={
            'request_id': request_id,
            'email': login_data.email,
            'client_ip': client_ip,
            'endpoint': 'login'
        }
    )
    
    # Authenticate user
    user = user_service.authenticate_user(
        login_data.email,
        login_data.password,
        request_id,
        client_ip
    )
    
    if user:
        logger.info(
            "Login successful",
            extra={
                'request_id': request_id,
                'user_id': user.id,
                'email': login_data.email,
                'endpoint': 'login'
            }
        )
        
        return {
            "message": "Login successful",
            "user": user.dict(),
            "token": "demo-jwt-token"  # In real app, generate actual JWT
        }
    else:
        logger.warning(
            "Login failed",
            extra={
                'request_id': request_id,
                'email': login_data.email,
                'client_ip': client_ip,
                'endpoint': 'login'
            }
        )
        
        raise HTTPException(status_code=401, detail="Invalid credentials")


@app.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    request: Request,
    request_id: str = Depends(get_request_id)
):
    """Get user by ID with logging."""
    logger = get_logger('app.endpoints.users')
    
    logger.info(
        "Get user endpoint called",
        extra={
            'request_id': request_id,
            'user_id': user_id,
            'endpoint': 'get_user'
        }
    )
    
    if user_id in user_service.users:
        user_data = user_service.users[user_id]
        return UserResponse(**user_data)
    else:
        logger.warning(
            "User not found",
            extra={
                'request_id': request_id,
                'user_id': user_id,
                'endpoint': 'get_user'
            }
        )
        raise HTTPException(status_code=404, detail="User not found")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    logger = get_logger('app.health')
    logger.debug("Health check performed")
    return {"status": "healthy", "timestamp": time.time()}


if __name__ == "__main__":
    import uvicorn
    
    # Configure uvicorn logging to work with our system
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8000,
        log_config=None,  # Disable uvicorn's default logging config
        access_log=False  # We handle access logs in our middleware
    ) 