from typing import Optional
from pydantic import BaseModel


class RoleCreate(BaseModel):
    name: str
    description: str = ""


class PermissionCreate(BaseModel):
    name: str
    description: str = ""


class RoleUpdate(BaseModel):
    id: str
    name: str
    description: str = ""


class PermissionUpdate(BaseModel):
    id: str
    name: str
    description: str = ""


class RoleFilter(BaseModel):
    name: str = ""
    description: str = ""


class PermissionFilter(BaseModel):
    name: str = ""
    description: str = ""