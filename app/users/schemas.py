from typing import Optional
from uuid import UUID
from pydantic import BaseModel


class UserCreate(BaseModel):
    email: str
    name: Optional[str]
    password: Optional[str]


class UserUpdate(BaseModel):
    name: str


class LinkedAccountCreate(BaseModel):
    provider: str
    given_name: str
    family_name: str
    picture: str
    email: str