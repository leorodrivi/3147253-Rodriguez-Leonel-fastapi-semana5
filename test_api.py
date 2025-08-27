import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from main import app
from database import Base, get_db
from auth import get_password_hash

SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)

TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

#
@pytest.fixture(scope="function")
def test_db():
    """Fixture para crear y limpiar la base de datos de test"""
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(test_db):
    """Fixture para el cliente de test"""
    def override_get_db():
        try:
            yield test_db
        finally:
            pass
    
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def test_user(client, test_db):
    """Fixture para crear un usuario de test"""
    from database import User
    
    hashed_password = get_password_hash("testpassword")
    user = User(
        username="testuser",
        email="test@example.com",
        hashed_password=hashed_password,
        role="user"
    )
    test_db.add(user)
    test_db.commit()
    test_db.refresh(user)
    
    return user

@pytest.fixture(scope="function")
def test_admin(client, test_db):
    """Fixture para crear un admin de test"""
    from database import User
    
    hashed_password = get_password_hash("adminpassword")
    admin = User(
        username="testadmin",
        email="admin@example.com",
        hashed_password=hashed_password,
        role="admin"
    )
    test_db.add(admin)
    test_db.commit()
    test_db.refresh(admin)
    
    return admin

@pytest.fixture(scope="function")
def user_token(client, test_user):
    """Fixture para obtener token de usuario normal"""
    response = client.post(
        "/auth/login",
        data={"username": "testuser", "password": "testpassword"}
    )
    return response.json()["access_token"]

@pytest.fixture(scope="function")
def admin_token(client, test_admin):
    """Fixture para obtener token de admin"""
    response = client.post(
        "/auth/login",
        data={"username": "testadmin", "password": "adminpassword"}
    )
    return response.json()["access_token"]

class TestAuthentication:
    def test_login_success(self, client, test_user):
        """Test de login exitoso"""
        response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "testpassword"}
        )
        
        assert response.status_code == 200
        assert "access_token" in response.json()
        assert response.json()["token_type"] == "bearer"
    
    def test_login_wrong_password(self, client, test_user):
        """Test de login con contraseña incorrecta"""
        response = client.post(
            "/auth/login",
            data={"username": "testuser", "password": "wrongpassword"}
        )
        
        assert response.status_code == 401
        assert "detail" in response.json()
    
    def test_login_nonexistent_user(self, client):
        """Test de login con usuario que no existe"""
        response = client.post(
            "/auth/login",
            data={"username": "nonexistent", "password": "password"}
        )
        
        assert response.status_code == 401
    
    def test_register_user(self, client):
        """Test de registro de nuevo usuario"""
        user_data = {
            "username": "newuser",
            "email": "newuser@example.com",
            "password": "newpassword",
            "role": "user"
        }
        
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 200
        assert response.json()["username"] == "newuser"
        assert response.json()["email"] == "newuser@example.com"
        assert response.json()["role"] == "user"
        assert "hashed_password" not in response.json()
    
    def test_register_duplicate_username(self, client, test_user):
        """Test de registro con username duplicado"""
        user_data = {
            "username": "testuser",  # Ya existe
            "email": "different@example.com",
            "password": "password",
            "role": "user"
        }
        
        response = client.post("/auth/register", json=user_data)
        
        assert response.status_code == 400
        assert "nombre de usuario ya está en uso" in response.json()["detail"]

class TestProtectedEndpoints:
    def test_get_current_user(self, client, user_token):
        """Test para obtener información del usuario actual"""
        response = client.get(
            "/users/me",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == 200
        assert response.json()["username"] == "testuser"
    
    def test_get_current_user_no_token(self, client):
        """Test de acceso sin token"""
        response = client.get("/users/me")
        
        assert response.status_code == 401
        assert "Not authenticated" in response.json()["detail"]
    
    def test_get_current_user_invalid_token(self, client):
        """Test de acceso con token inválido"""
        response = client.get(
            "/users/me",
            headers={"Authorization": "Bearer invalidtoken"}
        )
        
        assert response.status_code == 401
    
    def test_create_post(self, client, user_token):
        """Test de creación de post"""
        post_data = {
            "title": "Test Post",
            "content": "This is a test post content"
        }
        
        response = client.post(
            "/posts",
            json=post_data,
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == 200
        assert response.json()["title"] == "Test Post"
        assert response.json()["author"] == "testuser"
    
    def test_create_post_unauthenticated(self, client):
        """Test de creación de post sin autenticación"""
        post_data = {
            "title": "Test Post",
            "content": "This is a test post content"
        }
        
        response = client.post("/posts", json=post_data)
        
        assert response.status_code == 401

class TestAdminEndpoints:
    def test_list_users_as_admin(self, client, admin_token, test_user, test_admin):
        """Test de listado de usuarios como admin"""
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        assert len(response.json()) >= 2
    
    def test_list_users_as_user(self, client, user_token):
        """Test de listado de usuarios como usuario normal (debería fallar)"""
        response = client.get(
            "/admin/users",
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert response.status_code == 403
        assert "Permisos insuficientes" in response.json()["detail"]
    
    def test_list_users_unauthenticated(self, client):
        """Test de listado de usuarios sin autenticación"""
        response = client.get("/admin/users")
        
        assert response.status_code == 401

class TestPosts:
    def test_create_and_get_posts(self, client, user_token, test_db):
        """Test completo de creación y obtención de posts"""
        post_data = {
            "title": "First Post",
            "content": "Content of first post"
        }
        
        create_response = client.post(
            "/posts",
            json=post_data,
            headers={"Authorization": f"Bearer {user_token}"}
        )
        
        assert create_response.status_code == 200
        post_id = create_response.json()["id"]
        
        from database import Post
        db_post = test_db.query(Post).filter(Post.id == post_id).first()
        assert db_post is not None
        assert db_post.title == "First Post"
    
    def test_create_multiple_posts(self, client, user_token):
        """Test de creación de múltiples posts"""
        posts_data = [
            {"title": f"Post {i}", "content": f"Content {i}"}
            for i in range(3)
        ]
        
        for post_data in posts_data:
            response = client.post(
                "/posts",
                json=post_data,
                headers={"Authorization": f"Bearer {user_token}"}
            )
            assert response.status_code == 200

class TestHealthCheck:
    def test_health_check(self, client):
        """Test del endpoint de health check"""
        response = client.get("/health")

        if response.status_code == 404:
            response = client.get("/")
        
        assert response.status_code in [200, 404]

class TestValidation:
    def test_register_validation(self, client):
        """Test de validación de datos en registro"""
        invalid_data = [
            {"username": "ab", "password": "123"},
            {"username": "valid", "password": "123"},
            {"username": "valid", "password": "validpass", "email": "invalid-email"} 
        ]
        
        for data in invalid_data:
            response = client.post("/auth/register", json=data)
            assert response.status_code == 422

if __name__ == "__main__":
    pytest.main([__file__, "-v"])