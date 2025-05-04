import os
from datetime import datetime
from typing import Optional, List
from sqlmodel import Field, SQLModel, create_engine, Session, Relationship

# Database URL
# DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://myuser:1234@localhost/jwt_rbac_db")
DATABASE_URL = "postgresql+psycopg2://myuser:1234@localhost/jwt_rbac_db"

# SQLModel models
class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(unique=True, index=True)
    hashed_password: str
    role: str  # "user" or "admin"
    is_active: bool = Field(default=True)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    projects: List["Project"] = Relationship(back_populates="creator")

class Project(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    description: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[int] = Field(default=None, foreign_key="user.id")
    creator: Optional[User] = Relationship(back_populates="projects")

# Database engine creation
engine = create_engine(DATABASE_URL)

def create_db_and_tables():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

# Create tables on import
create_db_and_tables()