from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from typing import List

from app.core.db import get_db
from app.rbac.models import RolePermission, UserRole
from app.rbac.services import RoleService, PermissionService, RBACService
from app.rbac.schemas import (
    RoleCreate, RoleUpdate, RoleFilter,
    PermissionCreate, PermissionUpdate, PermissionFilter
)
from app.users.services import UserService
from app.users.schemas import UserCreate, UserUpdate
from app.auth.schemas import UserResponse
from .schemas import RoleResponse, PermissionResponse, UserRoleCreate, RolePermissionCreate


router = APIRouter()


# Role endpoints
@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role: RoleCreate,
    db: AsyncSession = Depends(get_db)
):
    role_service = RoleService(db)
    return await role_service.create_role(role)


@router.get("/roles", response_model=List[RoleResponse])
async def get_roles(
    filter: RoleFilter = Depends(),
    db: AsyncSession = Depends(get_db)
):
    role_service = RoleService(db)
    return await role_service.get_roles(filter)


@router.put("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    role_update: RoleUpdate,
    db: AsyncSession = Depends(get_db)
):
    role_service = RoleService(db)
    role_update.id = role_id
    return await role_service.update_role(role_update)


# Permission endpoints
@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission: PermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    permission_service = PermissionService(db)
    return await permission_service.create_permission(permission)


@router.get("/permissions", response_model=List[PermissionResponse])
async def get_permissions(
    filter: PermissionFilter = Depends(),
    db: AsyncSession = Depends(get_db)
):
    permission_service = PermissionService(db)
    return await permission_service.get_permissions(filter)


@router.put("/permissions/{permission_id}", response_model=PermissionResponse)
async def update_permission(
    permission_id: str,
    permission_update: PermissionUpdate,
    db: AsyncSession = Depends(get_db)
):
    permission_service = PermissionService(db)
    permission_update.id = permission_id
    return await permission_service.update_permission(permission_update)


# User endpoints
@router.post("/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user: UserCreate,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    user = await user_service.create_user(user)
    return {
        "id": user.id,
        "email": user.email,
        "name": user.name,
        "is_active": user.is_active,
        "is_verified": user.is_verified,
        "is_deleted": user.is_deleted,
    }


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    user = await user_service.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    return user


@router.get("/users", response_model=List[UserResponse])
async def get_users(
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    # Note: You may want to add pagination and filtering for users
    # This is a basic implementation
    return await user_service.get_all_users()


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    user_update: UserUpdate,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    user_update.id = user_id
    return await user_service.update_user(user_update)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    user_service = UserService(db)
    await user_service.delete_user(user_id)


# RBAC endpoints
@router.post("/users/{user_id}/roles", response_model=UserRole, status_code=status.HTTP_201_CREATED)
async def assign_role_to_user(
    user_id: str,
    role_assignment: UserRoleCreate,
    db: AsyncSession = Depends(get_db)
):
    rbac_service = RBACService(db)
    return await rbac_service.assign_role_to_user(user_id, role_assignment.role_id)


@router.post("/roles/{role_id}/permissions", response_model=RolePermission, status_code=status.HTTP_201_CREATED)
async def assign_permission_to_role(
    role_id: str,
    permission_assignment: RolePermissionCreate,
    db: AsyncSession = Depends(get_db)
):
    rbac_service = RBACService(db)
    return await rbac_service.assign_permission_to_role(role_id, permission_assignment.permission_id)


__all__ = ['router']