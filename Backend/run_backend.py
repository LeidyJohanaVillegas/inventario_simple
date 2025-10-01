#!/usr/bin/env python3
"""
Script para ejecutar SOLO el backend desde el directorio Backend
"""
import os
import sys

# Asegurar que estamos en el directorio correcto
if not os.path.exists('app'):
    print("❌ Error: Ejecutar desde el directorio Backend")
    sys.exit(1)

print("🚀 Iniciando Backend FastAPI...")
print("📍 URL: http://localhost:8081")
print("📚 Docs: http://localhost:8081/docs")
print("=" * 50)

# Importar y ejecutar
try:
    from app.main import app
    import uvicorn
    
    uvicorn.run(
        app, 
        host="localhost", 
        port=8081,
        reload=False,
        log_level="info"
    )
except KeyboardInterrupt:
    print("\n🛑 Servidor detenido por el usuario")
except Exception as e:
    print(f"❌ Error: {e}")
    input("Presiona Enter para salir...")
