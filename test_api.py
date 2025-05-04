import os
import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from main import app
from models import User, Project
from auth import hash_password

# Use in-memory SQLite for testing
@pytest.fixture
def client():
    # Create an in-memory database for testing
    TEST_DATABASE_URL = "sqlite:///:memory:"
    
    # Create a test engine
    test_engine = create_engine(
        TEST_DATABASE_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    
    # Create tables for testing
    SQLModel.metadata.create_all(test_engine)
    
    # Override the get_session dependency
    def get_test_session():
        with Session(test_engine) as session:
            yield session
    
    # Override the get_session dependency in the app
    from main import get_session
    app.dependency_overrides[get_session] = get_test_session
    
    # Create test users
    with Session(test_engine) as session:
        # Create admin user
        admin_user = User(
            username="admin",
            hashed_password=hash_password("adminpass"),
            role="admin"
        )
        session.add(admin_user)
        
        # Create regular user
        regular_user = User(
            username="user",
            hashed_password=hash_password("userpass"),
            role="user"
        )
        session.add(regular_user)
        
        # Commit users
        session.commit()
    
    # Create test client
    client = TestClient(app)
    
    # Return test client
    yield client
    
    # Clean up (remove dependency override)
    app.dependency_overrides.clear()

def test_register_user(client):
    response = client.post(
        "/register",
        json={"username": "testuser", "password": "testpass", "role": "user"}
    )
    assert response.status_code == 200
    assert response.json() == {"message": "User registered successfully"}

def test_register_duplicate_user(client):
    # First registration should succeed
    response = client.post(
        "/register",
        json={"username": "duplicate", "password": "testpass", "role": "user"}
    )
    assert response.status_code == 200
    
    # Second registration with same username should fail
    response = client.post(
        "/register",
        json={"username": "duplicate", "password": "testpass", "role": "user"}
    )
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]

def test_login(client):
    # Login with existing test user
    response = client.post(
        "/login",
        data={"username": "user", "password": "userpass"}
    )
    assert response.status_code == 200
    assert "access_token" in response.json()
    assert response.json()["token_type"] == "bearer"

def test_login_invalid_credentials(client):
    response = client.post(
        "/login",
        data={"username": "user", "password": "wrongpass"}
    )
    assert response.status_code == 401

def test_get_projects_unauthorized(client):
    response = client.get("/projects")
    assert response.status_code == 401

def test_create_project_as_admin(client):
    # Login as admin
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "adminpass"}
    )
    token = login_response.json()["access_token"]
    
    # Create project
    response = client.post(
        "/projects",
        json={"name": "Test Project", "description": "Test Description"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["name"] == "Test Project"
    assert response.json()["description"] == "Test Description"

def test_create_project_as_user(client):
    # Login as regular user
    login_response = client.post(
        "/login",
        data={"username": "user", "password": "userpass"}
    )
    token = login_response.json()["access_token"]
    
    # Try to create project (should fail due to insufficient permissions)
    response = client.post(
        "/projects",
        json={"name": "User Project", "description": "User Description"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 403

def test_get_projects_as_user(client):
    # First login as admin and create a project
    admin_login = client.post(
        "/login",
        data={"username": "admin", "password": "adminpass"}
    )
    admin_token = admin_login.json()["access_token"]
    
    client.post(
        "/projects",
        json={"name": "Admin Project", "description": "Admin Description"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    
    # Now login as regular user and get projects
    user_login = client.post(
        "/login",
        data={"username": "user", "password": "userpass"}
    )
    user_token = user_login.json()["access_token"]
    
    response = client.get(
        "/projects",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 200
    assert len(response.json()) > 0  # Should see the admin's project

def test_update_project_as_admin(client):
    # Login as admin
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "adminpass"}
    )
    token = login_response.json()["access_token"]
    
    # Create project
    create_response = client.post(
        "/projects",
        json={"name": "Project to Update", "description": "Initial Description"},
        headers={"Authorization": f"Bearer {token}"}
    )
    project_id = create_response.json()["id"]
    
    # Update project
    update_response = client.put(
        f"/projects/{project_id}",
        json={"name": "Updated Project", "description": "Updated Description"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert update_response.status_code == 200
    assert update_response.json()["name"] == "Updated Project"
    assert update_response.json()["description"] == "Updated Description"

def test_delete_project_as_admin(client):
    # Login as admin
    login_response = client.post(
        "/login",
        data={"username": "admin", "password": "adminpass"}
    )
    token = login_response.json()["access_token"]
    
    # Create project
    create_response = client.post(
        "/projects",
        json={"name": "Project to Delete", "description": "To be deleted"},
        headers={"Authorization": f"Bearer {token}"}
    )
    project_id = create_response.json()["id"]
    
    # Delete project
    delete_response = client.delete(
        f"/projects/{project_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert delete_response.status_code == 200
    assert delete_response.json()["message"] == "Project deleted successfully"
    
    # Verify it's gone
    get_response = client.get(
        f"/projects/{project_id}",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert get_response.status_code == 404

def test_update_project_as_user(client):
    # Login as admin to create a project
    admin_login = client.post(
        "/login",
        data={"username": "admin", "password": "adminpass"}
    )
    admin_token = admin_login.json()["access_token"]
    
    # Create project
    create_response = client.post(
        "/projects",
        json={"name": "Admin's Project", "description": "Admin's Description"},
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    project_id = create_response.json()["id"]
    
    # Login as regular user
    user_login = client.post(
        "/login",
        data={"username": "user", "password": "userpass"}
    )
    user_token = user_login.json()["access_token"]
    
    # Try to update project (should fail)
    update_response = client.put(
        f"/projects/{project_id}",
        json={"name": "User's Update", "description": "User's Description"},
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert update_response.status_code == 403