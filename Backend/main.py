from fastapi import FastAPI, HTTPException
from typing import List
from model import UsuarioCreate, UsuarioResponse  # Importa los modelos de Pydantic
from pool import get_db_connection  # Importa la función para obtener la conexión a la base de datos
from pydantic import BaseModel

app = FastAPI()

# Funciones para interactuar con la base de datos
def create_usuario(usuario: UsuarioCreate):
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)
        query = """
        INSERT INTO usuarios (rol, tipo_documento, documento, password)
        VALUES (%s, %s, %s, %s)
        """
        cursor.execute(query, (usuario.rol, usuario.tipo_documento, usuario.documento, usuario.password))
        connection.commit()
        cursor.close()
        connection.close()
        return {"msg": "Usuario creado exitosamente"}

    except Exception as e:
        print(f"Error al crear usuario: {e}")
        raise HTTPException(status_code=500, detail="Error al crear usuario")

def get_usuarios() -> List[UsuarioResponse]:
    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        query = "SELECT * FROM usuarios"
        cursor.execute(query)
        rows = cursor.fetchall()

        usuarios = [UsuarioResponse(**row) for row in rows]
        cursor.close()
        connection.close()

        return usuarios

    except Exception as e:
        print(f"Error al obtener usuarios: {e}")
        raise HTTPException(status_code=500, detail="Error al obtener usuarios")


# Rutas de la API
@app.post("/usuarios/", response_model=dict)
def create_usuario_view(usuario: UsuarioCreate):
    return create_usuario(usuario)

@app.get("/usuarios/", response_model=List[UsuarioResponse])
def get_usuarios_view():
    return get_usuarios()

from pydantic import BaseModel

class LoginRequest(BaseModel):
    documento: str
    password: str

@app.post("/login/")
def login(request: LoginRequest):
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    query = "SELECT * FROM usuarios WHERE documento = %s AND password = %s"
    cursor.execute(query, (request.documento, request.password))
    user = cursor.fetchone()

    cursor.close()
    connection.close()

    if not user:
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    return {"msg": "Login exitoso", "usuario": user}
