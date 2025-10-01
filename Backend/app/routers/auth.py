from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer
import bcrypt
import jwt
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from ..models import UsuarioLogin, UsuarioCreate, UsuarioResponse, TokenResponse, MessageResponse
from ..database import execute_query
from ..auth.security import verify_password, hash_password
from pydantic import BaseModel

# Modelos adicionales para auth
class LoginRequest(BaseModel):
    documento: str
    password: str

class LoginResponse(BaseModel):
    message: str
    user_id: int
    documento: str
    rol: str

class RegisterRequest(BaseModel):
    documento: str
    nombre: str
    email: str
    password: str
    rol: str

class RegisterResponse(BaseModel):
    message: str
    user_id: int
    documento: str

load_dotenv()

router = APIRouter()
security = HTTPBearer()

# Configuración JWT
SECRET_KEY = os.getenv("SECRET_KEY", "tu_clave_secreta_muy_segura")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

def hash_password(password: str) -> str:
    """Hashear contraseña con bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

def verify_password(password: str, hashed_password: str) -> bool:
    """Verificar contraseña con bcrypt"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict):
    """Crear token JWT"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def get_current_user(token: str = Depends(security)):
    """Obtener usuario actual desde el token"""

# Removed duplicate and broken /register and /login endpoints.


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    cnx = get_connection()

    try:
        # Buscar usuario por documento
        user = execute_query(
            "SELECT id, documento, nombre, email, rol, password_hash, activo FROM usuarios WHERE documento = %s",
            (credentials.documento,),
            fetch_one=True
        )
        
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        
        if not user['activo']:
            raise HTTPException(status_code=401, detail="Usuario inactivo")
        
        # Verificar contraseña
        if not verify_password(credentials.password, user['password_hash']):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        
        # Crear token
        access_token = create_access_token(data={"sub": str(user['id'])})
        
        # Preparar respuesta del usuario
        user_response = UsuarioResponse(
            id=user['id'],
            documento=user['documento'],
            nombre=user['nombre'],
            email=user['email'],
            rol=user['rol'],
            activo=user['activo']
        )
        
        return TokenResponse(
            access_token=access_token,
            token_type="bearer",
            user=user_response
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.post("/register", response_model=MessageResponse)
async def register(user_data: UsuarioCreate):
    """Registrar nuevo usuario"""
    try:
        # Verificar si el documento ya existe
        existing_user = execute_query(
            "SELECT id FROM usuarios WHERE documento = %s",
            (user_data.documento,),
            fetch_one=True
        )
        
        if existing_user:
            raise HTTPException(status_code=400, detail="El documento ya está registrado")
        
        # Verificar si el email ya existe (si se proporciona)
        if user_data.email:
            existing_email = execute_query(
                "SELECT id FROM usuarios WHERE email = %s",
                (user_data.email,),
                fetch_one=True
            )
            
            if existing_email:
                raise HTTPException(status_code=400, detail="El email ya está registrado")
        
        # Hashear contraseña
        hashed_password = hash_password(user_data.password)
        
        # Insertar nuevo usuario
        user_id = execute_query(
            """INSERT INTO usuarios (documento, nombre, email, password_hash, rol) 
               VALUES (%s, %s, %s, %s, %s)""",
            (user_data.documento, user_data.nombre, user_data.email, hashed_password, user_data.rol)
        )
        
        return MessageResponse(
            message=f"Usuario registrado exitosamente con ID: {user_id}",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error interno: {str(e)}")

@router.get("/me", response_model=UsuarioResponse)
async def get_current_user_info(current_user: UsuarioResponse = Depends(get_current_user)):
    """Obtener información del usuario actual"""
    return current_user


@router.post("/logout", response_model=MessageResponse)
async def logout():
    """Cerrar sesión (en una implementación real, invalidarías el token)"""
    return MessageResponse(
        message="Sesión cerrada exitosamente",
        success=True
    )
