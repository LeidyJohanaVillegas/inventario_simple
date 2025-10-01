#!/usr/bin/env python3
"""
Script para ejecutar SOLO el frontend
"""
import subprocess
import os
import sys

# Verificar que estamos en el directorio correcto
if not os.path.exists('package.json'):
    print("❌ Error: Ejecutar desde el directorio raíz del proyecto")
    sys.exit(1)

print("🚀 Iniciando Frontend React...")
print("📍 URL: http://localhost:5173")
print("=" * 50)

try:
    # Ejecutar npm run dev
    subprocess.run(["npm", "run", "dev"], check=True)
except KeyboardInterrupt:
    print("\n🛑 Frontend detenido por el usuario")
except subprocess.CalledProcessError as e:
    print(f"❌ Error ejecutando npm: {e}")
except FileNotFoundError:
    print("❌ Error: npm no encontrado. Instalar Node.js")
except Exception as e:
    print(f"❌ Error: {e}")

input("Presiona Enter para salir...")
