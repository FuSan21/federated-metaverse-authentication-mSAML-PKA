from typing import List
from datetime import datetime
from pydantic import BaseModel


class _UserBase(BaseModel):
    username: str


class UserCreate(_UserBase):
    deviceidhash: str
    public_key: str
    pass_username: str = None


class User(_UserBase):
    id: int
    is_active: bool
    pass_username: str
    deviceidhash: str

    class Config:
        from_attributes = True


class UpdateToken(BaseModel):
    access_token: str = None


class LoginToken(BaseModel):
    access_token: str = None
    refresh_token: str = None

class Challenge(BaseModel):
    pass_username: str
    deviceidhash: str
    challenge: str