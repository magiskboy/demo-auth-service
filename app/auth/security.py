from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from uuid import UUID

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from sqlmodel.ext.asyncio.session import AsyncSession

from app.core import settings
from app.core.db import get_db
from app.users.models import User
from app.users.services import UserService
from .schemas import TokenData, TokenType


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

security = HTTPBearer()
basic_security = HTTPBasic()


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against a hashed password."""
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """Hash a password."""
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "type": TokenType.ACCESS,
        "iat": datetime.now(timezone.utc)
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT refresh token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=7)  # Refresh tokens last 7 days
    
    to_encode.update({
        "exp": expire,
        "type": TokenType.REFRESH,
        "iat": datetime.now(timezone.utc)
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def verify_token(token: str, token_type: str = TokenType.ACCESS) -> TokenData:
    """Verify and decode a JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id: str = payload.get("sub")
        token_type_claim: str = payload.get("type")
        
        if user_id is None or token_type_claim != token_type:
            raise credentials_exception
            
        # Check if token is expired
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=timezone.utc) < datetime.now(timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )
            
        return TokenData(user_id=user_id, token_type=token_type_claim, exp=exp)
        
    except jwt.PyJWTError:
        raise credentials_exception


def create_token_pair(user_id: Union[str, UUID]) -> dict:
    """Create both access and refresh tokens for a user."""
    user_id_str = str(user_id)
    
    access_token = create_access_token(data={"sub": user_id_str})
    refresh_token = create_refresh_token(data={"sub": user_id_str})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60  # in seconds
    }


async def refresh_access_token(
    refresh_token: str,
    db: AsyncSession = Depends(get_db)
) -> dict:
    """Refresh an access token using a refresh token."""
    token_data = verify_token(refresh_token, TokenType.REFRESH)
    
    # Verify user still exists and is active
    user_service = UserService(db)
    user = await user_service.get_user(token_data.user_id)
    
    if not user or not user.is_active or user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token or user not found",
        )
    
    # Create new access token
    access_token = create_access_token(data={"sub": str(user.id)})
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }


async def authenticate_user(
    email: str, 
    password: str, 
    db: AsyncSession
) -> Optional[User]:
    """Authenticate a user with email and password."""
    user_service = UserService(db)
    user = await user_service.get_user_by_email(email)
    
    if not user:
        return None
    
    if not verify_password(password, user.password):
        return None
    
    return user


# ============= BASIC AUTHENTICATION =============

async def verify_basic_credentials(
    credentials: HTTPBasicCredentials = Depends(basic_security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Verify HTTP Basic authentication credentials."""
    basic_auth_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid authentication credentials",
        headers={"WWW-Authenticate": "Basic"},
    )
    
    if not credentials.username or not credentials.password:
        raise basic_auth_exception
    
    # Use the existing authenticate_user function
    user = await authenticate_user(credentials.username, credentials.password, db)
    
    if not user:
        raise basic_auth_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account has been deleted",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return user


async def get_current_user_bearer(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """Get the current authenticated user from JWT token."""
    token = credentials.credentials
    token_data = verify_token(token, TokenType.ACCESS)
    
    user_service = UserService(db)
    user = await user_service.get_user(token_data.user_id)
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if user.is_deleted:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account has been deleted",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user


async def get_current_user(
    bearer_credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    basic_credentials: Optional[HTTPBasicCredentials] = Depends(basic_security),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Get current user via either Bearer token or Basic authentication.
    Tries Bearer first, then Basic if Bearer is not provided.
    """
    # Try Bearer authentication first
    if bearer_credentials:
        try:
            return await get_current_user_bearer(bearer_credentials, db)
        except HTTPException:
            pass
    
    # Try Basic authentication
    if basic_credentials:
        try:
            return await verify_basic_credentials(basic_credentials, db)
        except HTTPException:
            pass
    
    # If both fail, raise authentication error
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials. Provide either Bearer token or Basic authentication.",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )


# Optional: Role-based access control decorators
def require_roles(*roles: str):
    """Decorator to require specific roles for accessing an endpoint."""
    def decorator(func):
        async def wrapper(*args, **kwargs):
            # Get current user from kwargs (assuming it's passed as dependency)
            current_user = None
            for key, value in kwargs.items():
                if isinstance(value, User):
                    current_user = value
                    break
            
            if not current_user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authentication required"
                )
            
            # Check if user has any of the required roles
            user_roles = [role.name for role in current_user.roles] if current_user.roles else []
            
            if not any(role in user_roles for role in roles):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Insufficient permissions. Required roles: {', '.join(roles)}"
                )
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator


async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current active user (additional check for active status)."""
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Inactive user"
        )
    return current_user


async def get_current_verified_user(current_user: User = Depends(get_current_user)) -> User:
    """Get the current verified user."""
    if not current_user.is_verified:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User email not verified"
        )
    return current_user


# Dependency for optional authentication (user can be None)
async def get_current_user_optional(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    """Get current user if authenticated, otherwise return None."""
    if not credentials:
        return None
    
    try:
        return await get_current_user(credentials, db)
    except HTTPException:
        return None
