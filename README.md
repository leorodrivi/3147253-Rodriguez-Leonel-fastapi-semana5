# 🔐 API con Autenticación JWT - FastAPI

## ¿Qué aprendimos?

### **Estructura del Proyecto**
```
mi_proyecto/
├── main.py          # App principal y endpoints
├── models.py        # Modelos de datos
├── schemas.py       # Esquemas Pydantic (request/response)
├── database.py      # Configuración de base de datos
├── auth.py          # Autenticación y seguridad
├── test_api.py      # Tests automatizados
└── requirements.txt # Dependencias
```

### **Autenticación JWT**
- **Tokens seguros** con expiración
- **Password hashing** con bcrypt
- **Login protegido** con verificación de credenciales
- **Endpoints protegidos** que requieren token

### **Sistema de Roles**
- **Usuarios normales** → Pueden crear posts
- **Administradores** → Acceso especial a endpoints admin

### **Base de Datos**
- **SQLAlchemy ORM** para operaciones type-safe
- **Modelos relacionales** (Users ↔ Posts)
- **Sesiones gestionadas** automáticamente

### **Testing**
- **Tests automatizados** con pytest
- **Base de datos en memoria** para testing
- **Pruebas de seguridad** (401, 403 errors)
- **Fixtures reutilizables** para datos de prueba

## **Endpoints Principales**

| Endpoint | Método | Descripción | Autenticación |
|----------|--------|-------------|---------------|
| `/auth/login` | POST | Login y obtener token | ❌ |
| `/auth/register` | POST | Registrar nuevo usuario | ❌ |
| `/users/me` | GET | Info del usuario actual | ✅ |
| `/posts` | POST | Crear nueva publicación | ✅ |
| `/admin/users` | GET | Listar usuarios (solo admin) | ✅ + Admin |

## **Cómo usar**

1. **Instalar dependencias:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Ejecutar la app:**
   ```bash
   uvicorn main:app --reload
   ```

3. **Probar en navegador:**
   ```
   http://localhost:8000/docs
   ```

4. **Ejecutar tests:**
   ```bash
   pytest test_api.py -v
   ```

## ✅ **Conceptos dominados**

- ✅ **JWT authentication**
- ✅ **Password security** 
- ✅ **Role-based authorization**
- ✅ **Database modeling**
- ✅ **API testing**
- ✅ **FastAPI dependencies**
