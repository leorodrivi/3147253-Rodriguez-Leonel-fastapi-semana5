from sqlalchemy import create_engine, Column, Integer, String, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
from datetime import datetime
import os
from typing import Generator

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

class User(Base):
    """Modelo de usuario para la base de datos"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(20), default="user", nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    posts = relationship("Post", back_populates="author")

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"

class Post(Base):
    """Modelo de publicación para la base de datos"""
    __tablename__ = "posts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    content = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    author = relationship("User", back_populates="posts")

    def __repr__(self):
        return f"<Post(id={self.id}, title='{self.title}', author_id={self.author_id})>"

def get_db() -> Generator[Session, None, None]:
    """
    Dependency para obtener sesión de base de datos.
    Usar en dependencias de FastAPI.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Inicializar la base de datos creando todas las tablas.
    Ejecutar al iniciar la aplicación.
    """
    Base.metadata.create_all(bind=engine)

def seed_database():
    """
    Poblar la base de datos con datos iniciales para desarrollo.
    """
    from passlib.context import CryptContext
    
    pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    db = SessionLocal()
    try:
        if db.query(User).count() == 0:
            users_data = [
                {
                    "username": "alice",
                    "email": "alice@example.com",
                    "hashed_password": pwd_context.hash("1234"),
                    "role": "admin",
                    "is_active": True
                },
                {
                    "username": "bob",
                    "email": "bob@example.com",
                    "hashed_password": pwd_context.hash("abcd"),
                    "role": "user",
                    "is_active": True
                }
            ]
            
            for user_data in users_data:
                user = User(**user_data)
                db.add(user)

            posts_data = [
                {
                    "title": "Bienvenido al sistema",
                    "content": "Este es el primer post del sistema. ¡Bienvenido!",
                    "author_id": 1
                },
                {
                    "title": "Cómo usar la API",
                    "content": "Aquí encontrarás información sobre cómo usar nuestra API REST.",
                    "author_id": 1
                }
            ]
            
            for post_data in posts_data:
                post = Post(**post_data)
                db.add(post)
            
            db.commit()
            print("✅ Base de datos poblada con datos iniciales")
        else:
            print("✅ Base de datos ya contiene datos, omitiendo seeding")
            
    except Exception as e:
        db.rollback()
        print(f"❌ Error al poblar la base de datos: {e}")
        raise
    finally:
        db.close()

def check_database_health() -> bool:
    """
    Verificar que la base de datos esté conectada y respondiendo.
    """
    try:
        with SessionLocal() as db:
            db.execute("SELECT 1")
        return True
    except Exception as e:
        print(f"Health check falló: {e}")
        return False

class DatabaseContext:
    """Context manager para manejar sesiones de base de datos"""
    
    def __enter__(self):
        self.db = SessionLocal()
        return self.db
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.db.close()

if __name__ == "__main__":
    init_db()
    seed_database()
    print("✅ Base de datos inicializada correctamente")