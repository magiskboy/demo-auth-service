from uuid import UUID
from pydantic import BaseModel


class RoleResponse(BaseModel):
    id: UUID
    name: str
    description: str


class PermissionResponse(BaseModel):
    id: UUID
    name: str
    description: str


class UserRoleCreate(BaseModel):
    user_id: UUID
    role_id: UUID


class RolePermissionCreate(BaseModel):
    role_id: UUID
    permission_id: UUID


class UserResponse(BaseModel):
    id: UUID
    email: str
    name: str
    is_active: bool
    is_verified: bool
    is_deleted: bool