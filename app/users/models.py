from typing import List
from uuid import UUID
from sqlmodel import Field, Relationship
from app.core.db import OAuthBaseModel
from app.rbac.models import Role, UserRole


class User(OAuthBaseModel, table=True):
    __tablename__ = "users"

    email: str = Field(unique=True)
    name: str = Field(default="")
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    password: str = Field(default="")
    is_deleted: bool = Field(default=False)
    
    roles: List["Role"] = Relationship(back_populates="users", link_model=UserRole)
    linked_accounts: List["LinkedAccount"] = Relationship(back_populates="user")


class LinkedAccount(OAuthBaseModel, table=True):
    __tablename__ = "linked_accounts"

    user_id: UUID = Field(foreign_key="users.id")
    provider: str = Field(index=True)
    given_name: str = Field(default="")
    family_name: str = Field(default="")
    picture: str = Field(default="")
    email: str = Field(default="")
    is_verified: bool = Field(default=False)
    sub: str = Field(index=True)

    user: User = Relationship(back_populates="linked_accounts")


__all__ = ["User", "LinkedAccount"]