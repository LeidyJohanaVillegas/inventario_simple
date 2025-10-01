# 🚀 Cómo Ejecutar el Sistema de Inventario SENA

## ✅ Sistema Funcionando Correctamente

El sistema ha sido completamente configurado según la documentación original del proyecto y está funcionando.

### 📍 URLs del Sistema:
- **Frontend**: http://localhost:5173
- **Backend**: http://127.0.0.1:8082  
- **API Docs**: http://127.0.0.1:8082/docs

---

## 🔧 Instrucciones de Ejecución

### Opción 1: Scripts Automáticos (Recomendado)

#### Para Windows:
```cmd
# Terminal 1 - Backend
start_backend.bat

# Terminal 2 - Frontend  
start_frontend.bat
```

### Opción 2: Ejecución Manual

#### Backend (Terminal 1):
```bash
cd Backend
python server.py
```

#### Frontend (Terminal 2):
```bash
npm run dev
```

---

## 👥 Usuarios de Prueba

El sistema incluye usuarios de prueba con las credenciales actualizadas según la documentación:

| Rol | Documento | Contraseña | Tipo Doc |
|-----|-----------|------------|----------|
| **Instructora** | `1001234567` | `instructor123` | CC |
| **Aprendiz** | `1056789123` | `aprendiz1234` | TI |
| **Inspector** | `1056789478` | `inspector12` | CC |

---

## 🎯 Funcionalidades Implementadas

### ✅ Según Documentación Original:
- **28 Clases** implementadas según `documentacionProyecto/Inventario_simple_SENA.txt`
- **ENUMs correctos**: Roles, categorías, tipos de documento
- **Métodos específicos**: changePassword, getOrdenes, getMovimientos, etc.
- **OAuth2 completo**: con refresh tokens y PKCE
- **QR y YOLO**: detección de productos con IA
- **Permisos por rol**: Instructora > Inspector > Aprendiz

### 🔧 Características Técnicas:
- **Backend**: FastAPI con SQLite (fácil migración a MySQL)
- **Frontend**: React + Vite con hot-reload
- **Autenticación**: JWT + OAuth2
- **Base de datos**: Inicializada con datos de prueba
- **CORS**: Configurado para desarrollo

---

## 🔍 Verificación del Sistema

### Probar Backend:
```bash
# Health check
curl http://127.0.0.1:8082/health

# API principal
curl http://127.0.0.1:8082/
```

### Probar Frontend:
1. Abrir http://localhost:5173
2. Login con usuarios de prueba
3. Verificar funcionalidades del inventario

---

## 📝 Notas Importantes

1. **Puertos**: Backend en 8082, Frontend en 5173
2. **Base de datos**: SQLite temporal (proyecto_final.db en Backend/)
3. **Configuración**: Vite configurado para proxy automático a backend
4. **Documentación**: Cumple 100% con documentacionProyecto/Inventario_simple_SENA.txt

---

## 🎉 Estado del Proyecto

**✅ SISTEMA COMPLETAMENTE FUNCIONAL**

- ✅ Backend ejecutándose correctamente
- ✅ Frontend ejecutándose correctamente  
- ✅ Comunicación entre servicios establecida
- ✅ Autenticación funcionando
- ✅ Base de datos inicializada
- ✅ Usuarios de prueba configurados
- ✅ Cumplimiento total con documentación original

**¡El sistema está listo para usar!** 🎯
