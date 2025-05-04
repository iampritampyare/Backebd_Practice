FastAPI JWT Authentication with RBAC
This project implements a RESTful API using FastAPI with JWT-based authentication and Role-Based Access Control (RBAC). It uses PostgreSQL as the database and SQLModel as the ORM.

Features
User registration and authentication
JWT-based token authentication
Role-Based Access Control (RBAC) with admin and user roles
CRUD operations for a "Project" resource with role-based restrictions
PostgreSQL database integration using SQLModel
Project Structure
.
├── main.py            # Main FastAPI application
├── models.py          # SQLModel models for database
├── auth.py            # Authentication and authorization utilities
├── requirements.txt   # Python dependencies
├── Dockerfile         # Docker configuration
├── docker-compose.yml # Docker Compose configuration
└── README.md          # Project documentation
Prerequisites
Python 3.8+
PostgreSQL
Docker and Docker Compose (optional, for containerized setup)
Installation and Setup
Option 1: Local Setup
Clone the repository:
bash
git clone https://github.com/yourusername/fastapi-jwt-rbac.git
cd fastapi-jwt-rbac
Create and activate a virtual environment:
bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install the dependencies:
bash
pip install -r requirements.txt
Set up PostgreSQL:
Install PostgreSQL if not already installed
Create a database named jwt_rbac_db
Update the database URL in models.py if needed
Run the application:
bash
uvicorn main:app --reload
Option 2: Docker Setup
Clone the repository:
bash
git clone https://github.com/yourusername/fastapi-jwt-rbac.git
cd fastapi-jwt-rbac
Build and run the Docker containers:
bash
docker-compose up --build
API Endpoints
Authentication Endpoints
Register a new user
POST /register
Request Body:
json
{
  "username": "example",
  "password": "password123",
  "role": "user"  // or "admin"
}
Login and get access token
POST /login
Request Body:
json
{
  "username": "example",
  "password": "password123"
}
Response:
json
{
  "access_token": "JWT_TOKEN",
  "token_type": "bearer"
}


Project Endpoints
Get all projects (accessible to all authenticated users)


GET /projects
Headers: Authorization: Bearer JWT_TOKEN
Get a specific project (accessible to all authenticated users)


GET /projects/{project_id}
Headers: Authorization: Bearer JWT_TOKEN
Create a new project (accessible only to admin users)


POST /projects
Headers: Authorization: Bearer JWT_TOKEN
Request Body:
json
{
  "name": "Project A",
  "description": "Description of project A"
}


Update a project (accessible only to admin users)
PUT /projects/{project_id}
Headers: Authorization: Bearer JWT_TOKEN
Request Body:
json
{
  "name": "Updated Project A",
  "description": "Updated description of project A"
}


Delete a project (accessible only to admin users)
DELETE /projects/{project_id}
Headers: Authorization: Bearer JWT_TOKEN
User Endpoints
Get all users (accessible only to admin users)
GET /users
Headers: Authorization: Bearer JWT_TOKEN
Security Notes
In a production environment, always use a strong, randomly generated secret key for JWT signing.
Store sensitive configuration like the secret key in environment variables, not in the code.
Always use HTTPS in production.
Consider implementing token refresh mechanism for better security.
Testing the API
After starting the application, you can access the interactive API documentation at http://localhost:8000/docs.
Register a new user:
Use the /register endpoint to create a user (role: "user") and an admin (role: "admin").
Obtain an access token:
Use the /login endpoint with the credentials to get an access token.
Use the access token in the Authorize button in the Swagger UI:
Click on the "Authorize" button at the top right.
Enter your token in the format Bearer YOUR_TOKEN.
Test the endpoints with different user roles:
Try accessing admin-only endpoints with a regular user token.
Try accessing all endpoints with an admin token.
Video Demonstration
A video demonstration of setting up and using this project can be found here.

License
This project is licensed under the MIT License.















Testing the API

Access the interactive API documentation at http://localhost:8000/docs
Register users:

Register an admin user via the /register endpoint
Register a regular user


Login with either user to get JWT tokens
Use the "Authorize" button in Swagger UI to set your token
Test different endpoints with different user roles

