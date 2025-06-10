from datetime import datetime
from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class TokenType:
    ACCESS = "access"
    REFRESH = "refresh"


class TokenData(BaseModel):
    user_id: str
    token_type: str
    exp: Optional[datetime] = None


class UserResponse(BaseModel):
    id: UUID
    email: str
    name: str
    is_active: bool
    is_verified: bool
    is_deleted: bool