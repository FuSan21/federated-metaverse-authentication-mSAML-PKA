from pydantic import BaseModel


class _VisitorBase(BaseModel):
    username: str

class VisitorCreate(_VisitorBase):
    status: str

class Requirements(BaseModel):
    auth_type: str
    auth_algorithm: str
    challenge_type: str