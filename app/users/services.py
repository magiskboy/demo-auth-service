from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from .models import User, LinkedAccount
from .schemas import UserCreate, UserUpdate, LinkedAccountCreate


class UserService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_user(self, user: UserCreate) -> User:
        user_obj = User(email=user.email, name=user.name or "", password=user.password or "")
        self.db.add(user_obj)
        await self.db.commit()
        await self.db.refresh(user_obj)
        return user_obj
    
    async def get_user(self, user_id: str) -> Optional[User]:
        return await self.db.get(User, user_id)
    
    async def get_user_by_email(self, email: str) -> Optional[User]:
        result = await self.db.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()
    
    async def get_all_users(self) -> List[User]:
        result = await self.db.execute(select(User).where(User.is_deleted == False))
        return list(result.scalars().all())
    
    async def update_user(self, user_update: UserUpdate) -> User:
        user = await self.get_user(user_update.id)
        user.name = user_update.name
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def delete_user(self, user_id: str) -> User:
        user = await self.get_user(user_id)
        user.is_deleted = True
        await self.db.commit()
        await self.db.refresh(user)
        return user

    async def create_linked_account(self, linked_account: LinkedAccountCreate) -> LinkedAccount:
        email = linked_account.email
        if not email:
            raise ValueError("Email is required")
        
        user = await self.get_user_by_email(email)
        if not user:
            # Create user with default password for OAuth users
            user = await self.create_user(UserCreate(
                email=email, 
                name=linked_account.given_name,
                password="oauth_user"  # Default password for OAuth users
            ))

        # Check for existing linked account
        existing_account_result = await self.db.execute(
            select(LinkedAccount).where(
                LinkedAccount.user_id == user.id,
                LinkedAccount.provider == linked_account.provider
            )
        )
        existing_account = existing_account_result.scalar_one_or_none()
        
        if existing_account:
            raise ValueError("Linked account already exists")
        
        # Handle the 'sub' and 'is_verified' fields that might not be in the schema
        sub = getattr(linked_account, 'sub', f"oauth-{email}")
        is_verified = getattr(linked_account, 'is_verified', True)
        
        linked_account_obj = LinkedAccount(
            user_id=user.id,
            provider=linked_account.provider,
            given_name=linked_account.given_name,
            family_name=linked_account.family_name,
            picture=linked_account.picture,
            email=linked_account.email,
            is_verified=is_verified,
            sub=sub,
        )
        self.db.add(linked_account_obj)
        await self.db.commit()
        await self.db.refresh(linked_account_obj)
        return linked_account_obj