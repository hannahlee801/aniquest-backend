from pydantic import BaseModel

class CreateUserRequest(BaseModel):
    username: str
    full_name: str
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: str