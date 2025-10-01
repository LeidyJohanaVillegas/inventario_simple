#!/usr/bin/env python3
"""
Script para probar los endpoints principales del API
"""

import requests
import json
import time

def test_api_endpoints():
    """Prueba los endpoints principales del API"""
    
    base_url = "http://localhost:8000"
    
    print("🚀 PRUEBA DE ENDPOINTS DEL API")
    print("=" * 50)
    
    # Lista de endpoints a probar
    endpoints = [
        {
            "name": "Lista de Productos",
            "method": "GET",
            "url": f"{base_url}/api/productos/",
            "auth_required": False
        },
        {
            "name": "Materiales de Formación",
            "method": "GET", 
            "url": f"{base_url}/api/productos/materiales-formacion",
            "auth_required": False
        },
        {
            "name": "Estado de Stock",
            "method": "GET",
            "url": f"{base_url}/api/productos/estado-stock",
            "auth_required": False
        },
        {
            "name": "Reporte de Inventario",
            "method": "GET",
            "url": f"{base_url}/api/productos/reporte-inventario",
            "auth_required": False
        },
        {
            "name": "Lista de Lotes",
            "method": "GET",
            "url": f"{base_url}/api/lotes/",
            "auth_required": False
        },
        {
            "name": "Lista de Alertas",
            "method": "GET",
            "url": f"{base_url}/api/alertas/",
            "auth_required": False
        }
    ]
    
    # Probar endpoints sin autenticación
    print("\n📋 PROBANDO ENDPOINTS SIN AUTENTICACIÓN:")
    print("-" * 40)
    
    for endpoint in endpoints:
        try:
            print(f"\n🔍 Probando: {endpoint['name']}")
            print(f"   URL: {endpoint['url']}")
            
            response = requests.get(endpoint['url'], timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                print(f"   ✅ Status: {response.status_code}")
                if isinstance(data, list):
                    print(f"   📊 Registros: {len(data)}")
                else:
                    print(f"   📊 Datos: {type(data).__name__}")
            else:
                print(f"   ❌ Status: {response.status_code}")
                print(f"   📝 Error: {response.text}")
                
        except requests.exceptions.ConnectionError:
            print(f"   ❌ Error: No se puede conectar al servidor")
        except requests.exceptions.Timeout:
            print(f"   ❌ Error: Timeout")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # Probar login
    print("\n🔐 PROBANDO AUTENTICACIÓN:")
    print("-" * 40)
    
    login_data = {
        "documento": "1001234567",
        "password": "instructor123"
    }
    
    try:
        print(f"\n🔍 Probando Login")
        print(f"   Usuario: {login_data['documento']}")
        
        response = requests.post(
            f"{base_url}/api/auth/login",
            json=login_data,
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            user_id = data.get('user_id')
            user_rol = data.get('rol')
            mensaje = data.get('message')
            print(f"   ✅ {mensaje}")
            print(f"   👤 Usuario ID: {user_id}")
            print(f"   🎭 Rol: {user_rol}")
            
            # Ya no necesitamos probar endpoints con autenticación JWT
            print(f"\n✅ Autenticación completada sin token JWT")
                
        else:
            print(f"   ❌ Login falló: {response.status_code}")
            print(f"   📝 Error: {response.text}")
            
    except requests.exceptions.ConnectionError:
        print(f"   ❌ Error: No se puede conectar al servidor")
    except Exception as e:
        print(f"   ❌ Error: {e}")
    
    print("\n" + "=" * 50)
    print("🏁 PRUEBA COMPLETADA")

if __name__ == "__main__":
    test_api_endpoints()
