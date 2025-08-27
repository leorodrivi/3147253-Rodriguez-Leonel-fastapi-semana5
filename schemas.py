from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List
from datetime import datetime
from enum import Enum

class UserRole(str, Enum):
    """Roles de usuario disponibles"""
    ADMIN = "admin"
    USER = "user"


class Token(BaseModel):
    """Schema para respuesta de token JWT"""
    access_token: str
    token_type: str = "bearer"

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImV4cCI6MTY4...",
                "token_type": "bearer"
            }
        }

class TokenData(BaseModel):
    """Datos contenidos en el token JWT"""
    username: Optional[str] = None
    role: Optional[str] = None

class LoginRequest(BaseModel):
    """Schema para request de login"""
    username: str = Field(..., example="alice")
    password: str = Field(..., example="1234")


class UserBase(BaseModel):
    """Base schema para usuario"""
    username: str = Field(..., min_length=3, max_length=50, example="alice")
    email: Optional[EmailStr] = Field(None, example="alice@example.com")

class UserCreate(UserBase):
    """Schema para creación de usuario"""
    password: str = Field(..., min_length=4, example="1234")
    role: UserRole = Field(default=UserRole.USER, example="user")

class UserUpdate(BaseModel):
    """Schema para actualización de usuario"""
    email: Optional[EmailStr] = Field(None, example="alice.new@example.com")
    password: Optional[str] = Field(None, min_length=4, example="nueva_contraseña")

class UserResponse(UserBase):
    """Schema para respuesta de usuario (sin información sensible)"""
    role: UserRole = Field(..., example="admin")
    is_active: bool = Field(default=True, example=True)
    created_at: Optional[datetime] = Field(None, example="2023-01-01T12:00:00")

    class Config:
        from_attributes = True

class UserInDB(UserResponse):
    """Schema interno para usuario en base de datos"""
    hashed_password: str = Field(..., example="$2b$12$EixZaYVK1fsbw1ZfbX3OXe...")


class PostBase(BaseModel):
    """Base schema para publicaciones"""
    title: str = Field(..., min_length=1, max_length=200, example="Mi primera publicación")
    content: str = Field(..., min_length=1, example="Este es el contenido de mi publicación...")

class PostCreate(PostBase):
    """Schema para creación de publicación"""
    pass

class PostUpdate(BaseModel):
    """Schema para actualización de publicación"""
    title: Optional[str] = Field(None, min_length=1, max_length=200, example="Título actualizado")
    content: Optional[str] = Field(None, min_length=1, example="Contenido actualizado...")

class PostResponse(PostBase):
    """Schema para respuesta de publicación"""
    id: int = Field(..., example=1)
    author: str = Field(..., example="alice")
    created_at: datetime = Field(..., example="2023-01-01T12:00:00")
    updated_at: Optional[datetime] = Field(None, example="2023-01-02T10:30:00")

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Schema para respuesta de lista de usuarios"""
    users: List[UserResponse]
    total: int = Field(..., example=2)

class PostListResponse(BaseModel):
    """Schema para respuesta de lista de publicaciones"""
    posts: List[PostResponse]
    total: int = Field(..., example=5)
    page: int = Field(..., example=1)
    per_page: int = Field(..., example=10)


class UserRoleUpdate(BaseModel):
    """Schema para actualización de rol de usuario (solo admin)"""
    role: UserRole = Field(..., example="admin")

class UserStatusUpdate(BaseModel):
    """Schema para actualización de estado de usuario (solo admin)"""
    is_active: bool = Field(..., example=False)


class ErrorResponse(BaseModel):
    """Schema estándar para respuestas de error"""
    detail: str = Field(..., example="Credenciales inválidas")
    error_code: Optional[str] = Field(None, example="INVALID_CREDENTIALS")

class ValidationErrorResponse(BaseModel):
    """Schema para errores de validación"""
    detail: List[dict] = Field(..., example=[{"loc": ["body", "username"], "msg": "field required", "type": "value_error.missing"}])


class HealthCheckResponse(BaseModel):
    """Schema para health check"""
    status: str = Field(..., example="healthy")
    timestamp: datetime = Field(..., example="2023-01-01T12:00:00")
    version: str = Field(..., example="1.0.0")