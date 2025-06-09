from typing import List
from pydantic import BaseModel


class RoleResponse(BaseModel):
    id: str
    name: str
    description: str


class PermissionResponse(BaseModel):
    id: str
    name: str
    description: str


class UserRoleCreate(BaseModel):
    user_id: str
    role_id: str


class RolePermissionCreate(BaseModel):
    role_id: str
    permission_id: str


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    is_active: bool
    is_verified: bool
    is_deleted: bool
    roles: List[RoleResponse]