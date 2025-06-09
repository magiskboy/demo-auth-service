from typing import List
from sqlalchemy.ext.asyncio import AsyncSession
from .models import User
from .schemas import UserCreate, UserUpdate


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
