from typing import List
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Role, Permission, UserRole, RolePermission
from .schemas import RoleCreate, PermissionCreate, RoleUpdate, RoleFilter, PermissionUpdate, PermissionFilter


class RoleService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_role(self, role: RoleCreate) -> Role:
        role = Role(name=role.name, description=role.description)
        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)
        return role
    
    async def update_role(self, role: RoleUpdate) -> Role:
        role = await self.get_role(role.id)
        role.name = role.name
        role.description = role.description
        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)
        return role
    
    async def get_roles(self, filter: RoleFilter) -> List[Role]:
        return await self.db.exec(select(Role).where(Role.name == filter.name, Role.description == filter.description))


class PermissionService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_permission(self, permission: PermissionCreate) -> Permission:
        permission = Permission(name=permission.name, description=permission.description)
        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)
        return permission
    
    async def update_permission(self, permission: PermissionUpdate) -> Permission:
        permission = await self.get_permission(permission.id)
        permission.name = permission.name
        permission.description = permission.description
        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)
        return permission
    
    async def get_permissions(self, filter: PermissionFilter) -> List[Permission]:
        return await self.db.exec(select(Permission).where(Permission.name == filter.name, Permission.description == filter.description))


class RBACService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def assign_role_to_user(self, user_id: str, role_id: str) -> UserRole:
        user_role = UserRole(user_id=user_id, role_id=role_id)
        self.db.add(user_role)
        await self.db.commit()
        await self.db.refresh(user_role)
        return user_role
    
    async def assign_permission_to_role(self, role_id: str, permission_id: str) -> RolePermission:
        role_permission = RolePermission(role_id=role_id, permission_id=permission_id)
        self.db.add(role_permission)
        await self.db.commit()
        await self.db.refresh(role_permission)
        return role_permission