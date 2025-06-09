from typing import List
from uuid import UUID
from sqlmodel import Field, Relationship
from app.core.db import OAuthBaseModel
from app.users.models import User


class Role(OAuthBaseModel, table=True):
    __tablename__ = "roles"

    name: str = Field(unique=True)
    description: str = Field(default="")

    users: List[User] = Relationship(back_populates="roles")
    permissions: List["Permission"] = Relationship(back_populates="roles")


class Permission(OAuthBaseModel, table=True):
    __tablename__ = "permissions"
    
    name: str = Field(unique=True, description="have format '<HTTP method>:<path>' like 'GET:/api/v1/users'")
    description: str = Field(default="")


class UserRole(OAuthBaseModel, table=True):
    __tablename__ = "user_roles"
    
    user_id: UUID = Field(foreign_key="users.id")
    role_id: UUID = Field(foreign_key="roles.id")


class RolePermission(OAuthBaseModel, table=True):
    __tablename__ = "role_permissions"
    
    role_id: UUID = Field(foreign_key="roles.id")
    permission_id: UUID = Field(foreign_key="permissions.id")
