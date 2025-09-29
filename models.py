from sqlmodel import SQLModel, Field

class User(SQLModel, table=True):
    full_name: str
    email: str
    username: str = Field(primary_key=True)
    hashed_password: str
    disabled: bool | None = None