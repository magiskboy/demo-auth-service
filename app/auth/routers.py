from fastapi import APIRouter, Depends, Request, HTTPException, status, Form
from fastapi.responses import RedirectResponse
from sqlmodel.ext.asyncio.session import AsyncSession

from .schemas import TokenType, UserResponse
from app.core import settings
from .sso_config import oauth
from .security import (
    authenticate_user, create_token_pair, refresh_access_token, 
    get_password_hash, get_current_user, verify_token
)
from app.users.schemas import LinkedAccountCreate, UserCreate
from app.users.services import UserService
from app.users.models import User
from app.core.db import get_db
from app.core.redis import get_redis
from .signals import on_login, on_logout


router = APIRouter()

@router.post("/register", response_model=dict)
async def register(
    email: str = Form(...),
    password: str = Form(...),
    name: str = Form(""),
    db: AsyncSession = Depends(get_db)
):
    """Register a new user with email and password."""
    user_service = UserService(db)
    
    # Check if user already exists
    existing_user = await user_service.get_user_by_email(email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create new user
    hashed_password = get_password_hash(password)
    user_data = UserCreate(
        email=email,
        password=hashed_password,
        name=name
    )
    
    user = await user_service.create_user(user_data)
    
    # Create token pair
    tokens = create_token_pair(user.id)
    
    on_login.send(user.id)
    
    return {
        "message": "User registered successfully",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "name": user.name
        },
        **tokens
    }


@router.post("/login", response_model=dict)
async def login(
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Login with email and password."""
    user = await authenticate_user(email, password, db)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password"
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled"
        )
    
    # Create token pair
    tokens = create_token_pair(user.id)
    
    on_login.send(user.id)
    
    return {
        "message": "Login successful",
        "user": {
            "id": str(user.id),
            "email": user.email,
            "name": user.name
        },
        **tokens
    }


@router.post("/refresh", response_model=dict)
async def refresh_token(
    refresh_token: str = Form(...),
    db: AsyncSession = Depends(get_db)
):
    """Refresh access token using refresh token."""
    try:
        new_tokens = await refresh_access_token(refresh_token, db)
        return {
            "message": "Token refreshed successfully",
            **new_tokens
        }
    except HTTPException as e:
        raise e
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(current_user: User = Depends(get_current_user)):
    """Logout current user."""
    redis = get_redis()
    await redis.set(
        name=f"token:{current_user.id}:{TokenType.ACCESS}", 
        value="blacklisted", 
        ex=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
    )
    await redis.set(
        name=f"token:{current_user.id}:{TokenType.REFRESH}", 
        value="blacklisted", 
        ex=settings.REFRESH_TOKEN_EXPIRE_MINUTES * 60)

    on_logout.send(current_user.id)
    
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """Get current user information."""
    return current_user


@router.post("/verify-token")
async def verify_user_token(
    token: str = Form(...),
    token_type: str = Form("access")
):
    """Verify if a token is valid."""
    try:
        token_data = verify_token(token, token_type)
        return {
            "valid": True,
            "user_id": token_data.user_id,
            "token_type": token_data.token_type,
            "expires_at": token_data.exp
        }
    except HTTPException:
        return {"valid": False}


# OAuth2 Google endpoints
@router.get("/login/google")
async def login_via_google(request: Request):
    """Initiate Google OAuth2 login."""
    redirect_uri = request.url_for('callback_via_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/callback/google")
async def callback_via_google(request: Request, db: AsyncSession = Depends(get_db)):
    """Handle Google OAuth2 callback."""
    token = await oauth.google.authorize_access_token(request)
    user_info = token['userinfo']
    user_service = UserService(db)
    
    # Check if user already exists
    existing_user = await user_service.get_user_by_email(user_info['email'])
    
    if existing_user:
        # User exists, create token pair and login
        tokens = create_token_pair(existing_user.id)
        # You might want to redirect to a frontend page with tokens
        return RedirectResponse(url=f"/?access_token={tokens['access_token']}&refresh_token={tokens['refresh_token']}")
    else:
        # Create new user from Google info
        user_data = UserCreate(
            email=user_info['email'],
            name=f"{user_info.get('given_name', '')} {user_info.get('family_name', '')}".strip(),
            password="",  # No password for OAuth users
            is_verified=True  # Google accounts are pre-verified
        )
        
        user = await user_service.create_user(user_data)
        
        # Create linked account
        linked_account = LinkedAccountCreate(
            provider='google',
            given_name=user_info.get('given_name', ''),
            family_name=user_info.get('family_name', ''),
            picture=user_info.get('picture', ''),
            email=user_info['email'],
        )
        await user_service.create_linked_account(linked_account)
        
        # Create token pair
        tokens = create_token_pair(user.id)
        
        return RedirectResponse(url=f"/?access_token={tokens['access_token']}&refresh_token={tokens['refresh_token']}")


__all__ = ['router']