"""
Servidor final que funciona
"""
import sys
import os

print("Iniciando Backend FastAPI...")
print("URL: http://127.0.0.1:8082")
print("Docs: http://127.0.0.1:8082/docs")
print("=" * 40)

try:
    from app.main import app
    import uvicorn
    
    uvicorn.run(
        app,
        host="127.0.0.1",
        port=8082,
        reload=False,
        access_log=True
    )
except Exception as e:
    print(f"Error: {e}")
    input("Presiona Enter para salir...")
