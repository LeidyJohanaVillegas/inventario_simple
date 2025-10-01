#!/usr/bin/env python3
"""
Script para ejecutar el servidor FastAPI
"""

import uvicorn
import os
from dotenv import load_dotenv

def main():
    """Función principal para ejecutar el servidor"""
    # Cargar variables de entorno
    load_dotenv()
    
    # Configuración del servidor
    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))
    debug = os.getenv("DEBUG", "True").lower() == "true"
    
    print(f"🚀 Iniciando servidor FastAPI...")
    print(f"📍 Host: {host}")
    print(f"🔌 Puerto: {port}")
    print(f"🐛 Debug: {debug}")
    print(f"📚 Documentación: http://{host}:{port}/docs")
    
    # Ejecutar servidor
    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=debug,
        log_level="info" if not debug else "debug"
    )

if __name__ == "__main__":
    main()
