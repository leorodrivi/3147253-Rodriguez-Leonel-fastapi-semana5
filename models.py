from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class User(BaseModel):
    """Modelo para representar un usuario"""
    username: str
    role: str

    class Config:
        schema_extra = {
            "example": {
                "username": "alice",
                "role": "admin"
            }
        }

class UserInDB(User):
    """Modelo para usuario con contraseña hasheada (uso interno)"""
    hashed_password: str

class Token(BaseModel):
    """Modelo para respuesta de token JWT"""
    access_token: str
    token_type: str

    class Config:
        schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer"
            }
        }

class Post(BaseModel):
    """Modelo para publicaciones"""
    title: str
    content: str

    class Config:
        schema_extra = {
            "example": {
                "title": "Mi primera publicación",
                "content": "Este es el contenido de mi publicación..."
            }
        }

class PostResponse(Post):
    """Modelo para respuesta de publicaciones (incluye metadatos)"""
    id: int
    author: str
    created_at: Optional[datetime] = None

    class Config:
        schema_extra = {
            "example": {
                "id": 1,
                "title": "Mi primera publicación",
                "content": "Este es el contenido de mi publicación...",
                "author": "alice",
                "created_at": "2023-01-01T12:00:00"
            }
        }

class UserCreate(BaseModel):
    """Modelo para creación de usuarios (registro)"""
    username: str
    password: str
    role: str = "user"

    class Config:
        schema_extra = {
            "example": {
                "username": "nuevo_usuario",
                "password": "contraseña_segura",
                "role": "user"
            }
        }

class TokenData(BaseModel):
    """Modelo para datos del token JWT"""
    username: Optional[str] = None