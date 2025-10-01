"""
Router para endpoints adicionales de usuarios
Implementa métodos adicionales de la clase Usuario según la documentación
"""

from fastapi import APIRouter, HTTPException, Depends, Query, Form
from typing import List, Dict, Any, Optional
from pydantic import BaseModel

from ..services.usuario_service import usuario_service
from ..models import UsuarioResponse, MessageResponse
from .auth import get_current_user

router = APIRouter()

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class QRReadRequest(BaseModel):
    qr_data: str

@router.post("/change-password", response_model=MessageResponse)
async def change_password(
    password_data: ChangePasswordRequest,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Cambiar contraseña del usuario
    Implementa el método changePassword() de la clase Usuario
    """
    try:
        success = usuario_service.change_password(
            user_id=current_user.id,
            old_password=password_data.old_password,
            new_password=password_data.new_password
        )
        
        if not success:
            raise HTTPException(status_code=400, detail="Contraseña actual incorrecta")
        
        return MessageResponse(
            message="Contraseña cambiada exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al cambiar contraseña: {str(e)}")

@router.post("/verify-password")
async def verify_password(
    password: str = Form(...),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Verificar contraseña del usuario
    Implementa el método verifyPassword() de la clase Usuario
    """
    try:
        is_valid = usuario_service.verify_password(
            user_id=current_user.id,
            password=password
        )
        
        return {
            "valid": is_valid,
            "message": "Contraseña verificada" if is_valid else "Contraseña incorrecta"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar contraseña: {str(e)}")

@router.get("/mis-ordenes", response_model=List[Dict[str, Any]])
async def get_mis_ordenes(
    permisos: str = Query("user", description="Nivel de permisos: user, all"),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Obtener órdenes del usuario
    Implementa el método getOrdenes() de la clase Usuario
    """
    try:
        ordenes = usuario_service.get_ordenes(
            user_id=current_user.id,
            permisos=permisos
        )
        
        return ordenes
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener órdenes: {str(e)}")

@router.get("/mis-movimientos", response_model=List[Dict[str, Any]])
async def get_mis_movimientos(
    permisos: str = Query("user", description="Nivel de permisos: user, all"),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Obtener movimientos del usuario
    Implementa el método getMovimientos() de la clase Usuario
    """
    try:
        movimientos = usuario_service.get_movimientos(
            user_id=current_user.id,
            permisos=permisos
        )
        
        return movimientos
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimientos: {str(e)}")

@router.get("/productos-asignados", response_model=List[Dict[str, Any]])
async def get_productos_asignados(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Obtener productos asignados al usuario
    Implementa el método getProductosAsignados() de la clase Usuario
    """
    try:
        productos = usuario_service.get_productos_asignados(current_user.id)
        return productos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos asignados: {str(e)}")

@router.get("/permisos", response_model=Dict[str, bool])
async def get_permisos_usuario(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Obtener permisos del usuario
    Implementa los métodos puedeCrearProducto() y puedeGestionarMateriales()
    """
    try:
        permisos = usuario_service.get_user_permissions(current_user.id)
        return permisos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener permisos: {str(e)}")

@router.get("/puede-crear-producto")
async def puede_crear_producto(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Verificar si el usuario puede crear productos
    Implementa el método puedeCrearProducto() de la clase Usuario
    """
    try:
        puede_crear = usuario_service.puede_crear_producto(current_user.id)
        
        return {
            "puede_crear": puede_crear,
            "message": "Usuario autorizado para crear productos" if puede_crear else "Usuario no autorizado para crear productos"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar permisos: {str(e)}")

@router.get("/puede-gestionar-materiales")
async def puede_gestionar_materiales(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Verificar si el usuario puede gestionar materiales
    Implementa el método puedeGestionarMateriales() de la clase Usuario
    """
    try:
        puede_gestionar = usuario_service.puede_gestionar_materiales(current_user.id)
        
        return {
            "puede_gestionar": puede_gestionar,
            "message": "Usuario autorizado para gestionar materiales" if puede_gestionar else "Usuario no autorizado para gestionar materiales"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al verificar permisos: {str(e)}")

@router.post("/leer-qr", response_model=Dict[str, Any])
async def leer_qr(
    qr_request: QRReadRequest,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """
    Leer código QR y obtener producto
    Implementa el método leerQR() de la clase Usuario
    """
    try:
        producto = usuario_service.leer_qr(
            user_id=current_user.id,
            qr_data=qr_request.qr_data
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="No se encontró ningún producto para este código QR")
        
        return {
            "success": True,
            "message": "Producto encontrado exitosamente",
            "producto": producto
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al leer QR: {str(e)}")

@router.get("/estadisticas", response_model=Dict[str, Any])
async def get_estadisticas_usuario(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener estadísticas del usuario"""
    try:
        estadisticas = usuario_service.get_user_stats(current_user.id)
        return estadisticas
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")

@router.get("/perfil-completo", response_model=Dict[str, Any])
async def get_perfil_completo(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener perfil completo del usuario con todas sus relaciones"""
    try:
        # Información básica del usuario
        perfil = {
            "usuario": current_user.dict(),
            "permisos": usuario_service.get_user_permissions(current_user.id),
            "estadisticas": usuario_service.get_user_stats(current_user.id),
            "productos_asignados": len(usuario_service.get_productos_asignados(current_user.id))
        }
        
        return perfil
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener perfil: {str(e)}")

@router.get("/dashboard", response_model=Dict[str, Any])
async def get_dashboard_usuario(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Dashboard personalizado según el rol del usuario"""
    try:
        dashboard = {
            "usuario": {
                "nombre": current_user.nombre,
                "rol": current_user.rol,
                "documento": current_user.documento
            },
            "estadisticas": usuario_service.get_user_stats(current_user.id),
            "permisos": usuario_service.get_user_permissions(current_user.id)
        }
        
        # Agregar secciones específicas según el rol
        if current_user.rol == "instructor":
            dashboard["mensaje_bienvenida"] = "Bienvenido, Instructor. Tienes acceso completo al sistema."
            dashboard["acciones_rapidas"] = [
                "Crear productos",
                "Gestionar materiales", 
                "Administrar usuarios",
                "Ver reportes completos"
            ]
        elif current_user.rol == "inspector":
            dashboard["mensaje_bienvenida"] = "Bienvenido, Inspector. Puedes supervisar y gestionar el inventario."
            dashboard["acciones_rapidas"] = [
                "Crear productos",
                "Gestionar materiales",
                "Supervisar órdenes",
                "Ver reportes"
            ]
        elif current_user.rol == "aprendiz":
            dashboard["mensaje_bienvenida"] = "Bienvenido, Aprendiz. Puedes consultar y crear órdenes."
            dashboard["acciones_rapidas"] = [
                "Ver mis productos",
                "Crear órdenes",
                "Ver mis movimientos",
                "Consultar inventario"
            ]
        
        return dashboard
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener dashboard: {str(e)}")

@router.get("/actividad-reciente", response_model=List[Dict[str, Any]])
async def get_actividad_reciente(
    limit: int = Query(10, ge=1, le=50),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener actividad reciente del usuario"""
    try:
        # Obtener movimientos recientes
        movimientos = usuario_service.get_movimientos(current_user.id, "user")
        
        # Convertir a formato de actividad
        actividades = []
        for mov in movimientos[:limit]:
            actividades.append({
                "tipo": "movimiento",
                "accion": f"Movimiento de {mov.get('tipo', 'desconocido')}",
                "descripcion": f"{mov.get('cantidad', 0)} unidades de {mov.get('producto_nombre', 'producto')}",
                "fecha": mov.get('fecha_movimiento'),
                "detalles": mov
            })
        
        # Obtener órdenes recientes
        ordenes = usuario_service.get_ordenes(current_user.id, "user")
        
        for orden in ordenes[:limit//2]:
            actividades.append({
                "tipo": "orden",
                "accion": f"Orden {orden.get('estado_orden', 'pendiente')}",
                "descripcion": f"Orden #{orden.get('id_orden')} - {orden.get('proveedor_nombre', 'Sin proveedor')}",
                "fecha": orden.get('fecha_orden'),
                "detalles": orden
            })
        
        # Ordenar por fecha más reciente
        actividades.sort(key=lambda x: x['fecha'] or '', reverse=True)
        
        return actividades[:limit]
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener actividad: {str(e)}")
