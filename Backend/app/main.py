from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer
import uvicorn
from datetime import datetime
import os
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Importar routers
from .routers import auth, productos, lotes, alertas, movimientos, qr
from .database import get_database_connection

app = FastAPI(
    title="Sistema de Gestión de Inventario",
    description="API para el sistema de gestión de inventario con FastAPI",
    version="1.0.0"
)

# Configurar CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En producción, especificar dominios exactos
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Incluir routers
app.include_router(auth.router, prefix="/api/auth", tags=["Autenticación"])
app.include_router(productos.router, prefix="/api/productos", tags=["Productos"])
app.include_router(lotes.router, prefix="/api/lotes", tags=["Lotes"])
app.include_router(alertas.router, prefix="/api/alertas", tags=["Alertas"])
app.include_router(movimientos.router, prefix="/api/movimientos", tags=["Movimientos"])
app.include_router(qr.router, prefix="/api/qr", tags=["Códigos QR y Detección"])

@app.get("/")
async def root():
    return {
        "message": "Sistema de Gestión de Inventario API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health_check():
    try:
        # Verificar conexión a la base de datos
        conn = get_database_connection()
        if conn:
            conn.close()
            return {"status": "healthy", "database": "connected"}
        else:
            return {"status": "unhealthy", "database": "disconnected"}
    except Exception as e:
        return {"status": "unhealthy", "error": str(e)}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
