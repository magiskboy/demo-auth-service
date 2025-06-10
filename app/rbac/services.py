from typing import List, Optional
from sqlmodel import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import Role, Permission, UserRole, RolePermission
from .schemas import RoleCreate, PermissionCreate, RoleUpdate, RoleFilter, PermissionUpdate, PermissionFilter


class RoleService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_role(self, role: RoleCreate) -> Role:
        role_obj = Role(name=role.name, description=role.description or "")
        self.db.add(role_obj)
        await self.db.commit()
        await self.db.refresh(role_obj)
        return role_obj
    
    async def get_role(self, role_id: str) -> Optional[Role]:
        return await self.db.get(Role, role_id)
    
    async def update_role(self, role_update: RoleUpdate) -> Role:
        role = await self.get_role(role_update.id)
        if not role:
            raise ValueError("Role not found")
        role.name = role_update.name
        role.description = role_update.description or ""
        self.db.add(role)
        await self.db.commit()
        await self.db.refresh(role)
        return role
    
    async def get_roles(self, filter: RoleFilter) -> List[Role]:
        query = select(Role)
        if filter and filter.name:
            query = query.where(Role.name == filter.name)
        if filter and filter.description:
            query = query.where(Role.description == filter.description)
        result = await self.db.execute(query)
        return list(result.scalars().all())


class PermissionService:
    def __init__(self, db: AsyncSession):
        self.db: AsyncSession = db

    async def create_permission(self, permission: PermissionCreate) -> Permission:
        permission_obj = Permission(name=permission.name, description=permission.description or "")
        self.db.add(permission_obj)
        await self.db.commit()
        await self.db.refresh(permission_obj)
        return permission_obj
    
    async def get_permission(self, permission_id: str) -> Optional[Permission]:
        return await self.db.get(Permission, permission_id)
    
    async def update_permission(self, permission_update: PermissionUpdate) -> Permission:
        permission = await self.get_permission(permission_update.id)
        if not permission:
            raise ValueError("Permission not found")
        permission.name = permission_update.name
        permission.description = permission_update.description or ""
        self.db.add(permission)
        await self.db.commit()
        await self.db.refresh(permission)
        return permission
    
    async def get_permissions(self, filter: PermissionFilter) -> List[Permission]:
        query = select(Permission)
        if filter and filter.name:
            query = query.where(Permission.name == filter.name)
        if filter and filter.description:
            query = query.where(Permission.description == filter.description)
        result = await self.db.execute(query)
        return list(result.scalars().all())


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