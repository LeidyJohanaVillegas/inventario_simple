#!/usr/bin/env python3
"""
Script de inicialización de la base de datos
Ejecutar este script para crear las tablas y datos iniciales
"""

import os
import sys
from dotenv import load_dotenv

# Agregar el directorio actual al path para importar módulos
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.database import init_database, execute_query

def main():
    """Función principal para inicializar la base de datos"""
    print("🚀 Inicializando base de datos...")
    
    # Cargar variables de entorno
    load_dotenv()
    
    try:
        # Inicializar base de datos
        success = init_database()
        
        if success:
            print("✅ Base de datos inicializada correctamente")
            
            # Verificar que las tablas se crearon
            tables = execute_query("SHOW TABLES", fetch_all=True)
            print(f"📋 Tablas creadas: {len(tables)}")
            for table in tables:
                table_name = list(table.values())[0]
                print(f"   - {table_name}")
            
            # Verificar usuarios
            users = execute_query("SELECT COUNT(*) as count FROM usuarios", fetch_one=True)
            print(f"👥 Usuarios: {users['count']}")
            
            # Verificar productos
            products = execute_query("SELECT COUNT(*) as count FROM productos", fetch_one=True)
            print(f"📦 Productos: {products['count']}")
            
            # Verificar lotes 
            lots = execute_query("SELECT COUNT(*) as count FROM lotes", fetch_one=True)
            print(f"📋 Lotes: {lots['count']}")
            
            print("\n🎉 ¡Inicialización completada exitosamente!")
            print("\n📝 Usuarios de prueba disponibles:")
            print("   - Instructor: 1001234567 / instructor123")
            print("   - Aprendiz: 1056789123 / aprendiz1234")
            print("   - Inspector: 1056789478 / inspector12")
            
        else:
            print("❌ Error al inicializar la base de datos")
            sys.exit(1)
            
    except Exception as e:
        print(f"❌ Error durante la inicialización: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
