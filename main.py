from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlmodel import Session, select
from datetime import datetime, timedelta
from jose import JWTError, jwt
from typing import List, Optional
from pydantic import BaseModel

from models import User, Project, get_session
from auth import (
    hash_password, 
    verify_password, 
    create_access_token, 
    get_current_user, 
    get_current_active_user,
    RoleChecker
)

app = FastAPI(title="FastAPI JWT RBAC API")

# Constants
ACCESS_TOKEN_EXPIRE_MINUTES = 30
allow_admin = RoleChecker(["admin"])
allow_user_admin = RoleChecker(["user", "admin"])

# Token model
class Token(BaseModel):
    access_token: str
    token_type: str

# Registration model
class UserCreate(BaseModel):
    username: str
    password: str
    role: str = "user"  # Default role is "user"

# Project Create/Update model
class ProjectCreate(BaseModel):
    name: str
    description: str

@app.post("/register", response_model=dict)
def register_user(user_data: UserCreate, db: Session = Depends(get_session)):
    # Check if username already exists
    user_exists = db.exec(select(User).where(User.username == user_data.username)).first()
    if user_exists:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Validate role
    if user_data.role not in ["user", "admin"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid role. Must be 'user' or 'admin'"
        )
    
    # Create new user with hashed password
    hashed_password = hash_password(user_data.password)
    new_user = User(
        username=user_data.username,
        hashed_password=hashed_password,
        role=user_data.role
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User registered successfully"}

@app.post("/login", response_model=Token)
def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_session)
):
    # Authenticate user
    user = db.exec(select(User).where(User.username == form_data.username)).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Generate access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    return {"access_token": access_token, "token_type": "bearer"}

# Project endpoints
@app.get("/projects", response_model=List[Project])
def get_projects(
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user)
):
    # Any authenticated user can view projects
    projects = db.exec(select(Project)).all()
    return projects

@app.post("/projects", response_model=Project)
def create_project(
    project: ProjectCreate,
    db: Session = Depends(get_session),
    current_user: User = Depends(allow_admin)  # Only admin can create projects
):
    new_project = Project(
        name=project.name,
        description=project.description,
        created_by=current_user.id
    )
    
    db.add(new_project)
    db.commit()
    db.refresh(new_project)
    
    return new_project

@app.get("/projects/{project_id}", response_model=Project)
def get_project(
    project_id: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_active_user)  # Any authenticated user can view a project
):
    project = db.exec(select(Project).where(Project.id == project_id)).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    return project

@app.put("/projects/{project_id}", response_model=Project)
def update_project(
    project_id: int,
    project_update: ProjectCreate,
    db: Session = Depends(get_session),
    current_user: User = Depends(allow_admin)  # Only admin can update projects
):
    project = db.exec(select(Project).where(Project.id == project_id)).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    # Update project attributes
    project.name = project_update.name
    project.description = project_update.description
    
    db.add(project)
    db.commit()
    db.refresh(project)
    
    return project

@app.delete("/projects/{project_id}", response_model=dict)
def delete_project(
    project_id: int,
    db: Session = Depends(get_session),
    current_user: User = Depends(allow_admin)  # Only admin can delete projects
):
    project = db.exec(select(Project).where(Project.id == project_id)).first()
    if not project:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Project not found"
        )
    
    db.delete(project)
    db.commit()
    
    return {"message": "Project deleted successfully"}

# User endpoints - only for admins
@app.get("/users", response_model=List[User])
def get_users(
    db: Session = Depends(get_session),
    current_user: User = Depends(allow_admin)  # Only admin can view all users
):
    users = db.exec(select(User)).all()
    return users

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)