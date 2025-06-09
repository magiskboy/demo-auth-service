from typing import List, TYPE_CHECKING
from sqlmodel import Field, Relationship
from app.core.db import OAuthBaseModel

if TYPE_CHECKING:
    from app.rbac.models import Role


class User(OAuthBaseModel, table=True):
    __tablename__ = "users"

    email: str = Field(unique=True)
    name: str = Field(default="")
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    password: str = Field(default="")
    is_deleted: bool = Field(default=False)
    
    roles: List["Role"] = Relationship(back_populates="users")
