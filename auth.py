from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import database
import schemas
import models
from database import get_db

SECRET_KEY = "mi-clave-super-secreta"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verificar si la contraseña plana coincide con el hash
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Generar hash de contraseña
    """
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Crear token JWT de acceso
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    """
    Crear token JWT de refresh (válido por 7 días)
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=7)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_user_by_username(db: Session, username: str) -> Optional[models.User]:
    """
    Obtener usuario por username desde la base de datos
    """
    return db.query(models.User).filter(models.User.username == username).first()

def get_user_by_email(db: Session, email: str) -> Optional[models.User]:
    """
    Obtener usuario por email desde la base de datos
    """
    return db.query(models.User).filter(models.User.email == email).first()

def authenticate_user(db: Session, username: str, password: str) -> Optional[models.User]:
    """
    Autenticar usuario verificando credenciales
    """
    user = get_user_by_username(db, username)
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> models.User:
    """
    Obtener usuario actual desde el token JWT
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        token_data = schemas.TokenData(username=username)
    except JWTError:
        raise credentials_exception
    
    user = get_user_by_username(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inactivo"
        )
    
    return user

async def get_current_active_user(
    current_user: models.User = Depends(get_current_user)
) -> models.User:
    """
    Verificar que el usuario actual está activo
    """
    if not current_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inactivo"
        )
    return current_user

async def require_admin(
    current_user: models.User = Depends(get_current_active_user)
) -> models.User:
    """
    Verificar que el usuario actual es administrador
    """
    if current_user.role != schemas.UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permisos insuficientes. Se requiere rol de administrador"
        )
    return current_user

async def require_user_or_admin(
    current_user: models.User = Depends(get_current_active_user),
    user_id: Optional[int] = None
) -> models.User:
    """
    Verificar que el usuario actual es el dueño del recurso o administrador
    """
    if current_user.role == schemas.UserRole.ADMIN:
        return current_user
    
    if user_id and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Solo puedes acceder a tus propios recursos"
        )
    
    return current_user

def register_user(db: Session, user_data: schemas.UserCreate) -> models.User:
    """
    Registrar nuevo usuario en el sistema
    """
    if get_user_by_username(db, user_data.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El nombre de usuario ya está en uso"
        )

    if user_data.email and get_user_by_email(db, user_data.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El email ya está en uso"
        )

    hashed_password = get_password_hash(user_data.password)
    db_user = models.User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        role=user_data.role.value if isinstance(user_data.role, schemas.UserRole) else user_data.role
    )
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

def login_user(db: Session, form_data: OAuth2PasswordRequestForm) -> schemas.Token:
    """
    Iniciar sesión y generar tokens
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario o contraseña incorrectos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario inactivo"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username, "role": user.role},
        expires_delta=access_token_expires
    )
    
    return schemas.Token(access_token=access_token, token_type="bearer")

# --- Funciones de Cambio de Contraseña ---
def change_password(
    db: Session,
    user: models.User,
    current_password: str,
    new_password: str
) -> models.User:
    """
    Cambiar contraseña del usuario
    """
    if not verify_password(current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Contraseña actual incorrecta"
        )
    
    user.hashed_password = get_password_hash(new_password)
    db.commit()
    db.refresh(user)
    
    return user

def reset_password_request(db: Session, email: str) -> None:
    """
    Solicitar reseteo de contraseña (en producción, enviaría email)
    """
    user = get_user_by_email(db, email)
    if user:
        # En producción: generar token de reseteo y enviar email
        print(f"Password reset requested for user: {user.username}")
    # Siempre devolver éxito para no revelar qué emails existen

def reset_password(db: Session, token: str, new_password: str) -> None:
    """
    Resetear contraseña usando token válido
    """
    # En producción: verificar token y actualizar contraseña
    print(f"Password reset with token: {token}")
    # Implementar lógica real de verificación de token

# --- Función para verificar permisos de recurso ---
def verify_resource_ownership(
    current_user: models.User,
    resource_owner_id: int
) -> bool:
    """
    Verificar si el usuario actual es dueño del recurso o es admin
    """
    return current_user.role == schemas.UserRole.ADMIN or current_user.id == resource_owner_id