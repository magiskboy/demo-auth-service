from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from .models import User, LinkedAccount
from .schemas import UserCreate, UserUpdate, LinkedAccountCreate


class UserService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_user(self, user: UserCreate) -> User:
        user = User(email=user.email, name=user.name, password=user.password)
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def get_user(self, user_id: str) -> User:
        return await self.db.get(User, user_id)
    
    async def get_user_by_email(self, email: str) -> User:
        return await self.db.exec(select(User).where(User.email == email)).first()
    
    async def update_user(self, user: UserUpdate) -> User:
        user = await self.get_user(user.id)
        user.name = user.name
        self.db.add(user)
        await self.db.commit()
        await self.db.refresh(user)
        return user
    
    async def delete_user(self, user_id: str) -> None:
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
            user = await self.create_user(UserCreate(email=email, name=linked_account.given_name))

        if user.linked_accounts.filter(LinkedAccount.provider == linked_account.provider).first():
            raise ValueError("Linked account already exists")
        
        linked_account = LinkedAccount(
            user_id=user.id,
            provider=linked_account.provider,
            given_name=linked_account.given_name,
            family_name=linked_account.family_name,
            picture=linked_account.picture,
            email=linked_account.email,
            is_verified=linked_account.is_verified,
            sub=linked_account.sub,
        )
        self.db.add(linked_account)
        await self.db.commit()
        await self.db.refresh(linked_account)
        return linked_account