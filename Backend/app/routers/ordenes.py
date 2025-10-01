from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime, date
from decimal import Decimal

from ..models import (
    Orden, OrdenCreate, OrdenUpdate, OrdenResponse,
    OrdenDetalle, OrdenDetalleCreate, OrdenDetalleUpdate, OrdenDetalleResponse,
    EstadoOrden, MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

# ==================== RUTAS PARA ÓRDENES ====================

@router.get("/", response_model=List[dict])
async def get_ordenes(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    estado: Optional[EstadoOrden] = Query(None),
    proveedor_id: Optional[int] = Query(None),
    fecha_desde: Optional[date] = Query(None),
    fecha_hasta: Optional[date] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de órdenes con filtros"""
    try:
        # Construir consulta base
        query = """
            SELECT o.*, 
                   u.nombre as usuario_nombre, u.documento as usuario_documento,
                   p.nombre as proveedor_nombre
            FROM ordenes o
            JOIN usuarios u ON o.id_usuario = u.id
            LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
        """
        conditions = []
        params = []
        
        # Filtros por rol de usuario
        if current_user.rol == "aprendiz":
            conditions.append("o.id_usuario = %s")
            params.append(current_user.id)
        
        if estado:
            conditions.append("o.estado_orden = %s")
            params.append(estado.value)
        
        if proveedor_id:
            conditions.append("o.id_proveedor = %s")
            params.append(proveedor_id)
        
        if fecha_desde:
            conditions.append("DATE(o.fecha_orden) >= %s")
            params.append(fecha_desde)
        
        if fecha_hasta:
            conditions.append("DATE(o.fecha_orden) <= %s")
            params.append(fecha_hasta)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY o.fecha_orden DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        ordenes = execute_query(query, params, fetch_all=True)
        return ordenes
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener órdenes: {str(e)}")

@router.get("/{orden_id}", response_model=dict)
async def get_orden(
    orden_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener orden específica con sus detalles"""
    try:
        # Obtener orden
        orden = execute_query(
            """SELECT o.*, 
                      u.nombre as usuario_nombre, u.documento as usuario_documento,
                      p.nombre as proveedor_nombre, p.email as proveedor_email
               FROM ordenes o
               JOIN usuarios u ON o.id_usuario = u.id
               LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
               WHERE o.id_orden = %s""",
            (orden_id,),
            fetch_one=True
        )
        
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        # Verificar permisos - aprendices solo pueden ver sus propias órdenes
        if current_user.rol == "aprendiz" and orden['id_usuario'] != current_user.id:
            raise HTTPException(status_code=403, detail="No tiene permisos para ver esta orden")
        
        # Obtener detalles de la orden
        detalles = execute_query(
            """SELECT od.*, 
                      pr.nombre as producto_nombre, pr.codigo as producto_codigo,
                      pr.unidad_medida as producto_unidad
               FROM ordenes_detalles od
               JOIN productos pr ON od.id_producto = pr.id
               WHERE od.id_orden = %s
               ORDER BY pr.nombre""",
            (orden_id,),
            fetch_all=True
        )
        
        # Agregar detalles a la orden
        orden['detalles'] = detalles
        
        return orden
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener orden: {str(e)}")

@router.post("/", response_model=dict)
async def create_orden(
    orden_data: OrdenCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nueva orden"""
    try:
        # Verificar permisos - aprendices solo pueden crear órdenes para sí mismos
        if current_user.rol == "aprendiz" and orden_data.id_usuario != current_user.id:
            raise HTTPException(status_code=403, detail="Los aprendices solo pueden crear órdenes para sí mismos")
        
        # Verificar que el usuario existe
        usuario = execute_query(
            "SELECT id FROM usuarios WHERE id = %s",
            (orden_data.id_usuario,),
            fetch_one=True
        )
        
        if not usuario:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Verificar que el proveedor existe (si se especifica)
        if orden_data.id_proveedor:
            proveedor = execute_query(
                "SELECT id_proveedor FROM proveedores WHERE id_proveedor = %s",
                (orden_data.id_proveedor,),
                fetch_one=True
            )
            
            if not proveedor:
                raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Insertar nueva orden
        orden_id = execute_query(
            """INSERT INTO ordenes (id_usuario, id_proveedor, estado_orden, total)
               VALUES (%s, %s, %s, %s)""",
            (
                orden_data.id_usuario,
                orden_data.id_proveedor,
                orden_data.estado_orden.value,
                orden_data.total
            ),
            return_id=True
        )
        
        # Obtener la orden creada con sus relaciones
        orden = execute_query(
            """SELECT o.*, 
                      u.nombre as usuario_nombre, u.documento as usuario_documento,
                      p.nombre as proveedor_nombre
               FROM ordenes o
               JOIN usuarios u ON o.id_usuario = u.id
               LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
               WHERE o.id_orden = %s""",
            (orden_id,),
            fetch_one=True
        )
        
        orden['detalles'] = []  # Nueva orden sin detalles
        
        return orden
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear orden: {str(e)}")

@router.put("/{orden_id}", response_model=dict)
async def update_orden(
    orden_id: int,
    orden_data: OrdenUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar orden"""
    try:
        # Verificar si la orden existe y obtener información
        existing = execute_query(
            "SELECT id_usuario, estado_orden FROM ordenes WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        # Verificar permisos
        if current_user.rol == "aprendiz":
            if existing['id_usuario'] != current_user.id:
                raise HTTPException(status_code=403, detail="No tiene permisos para actualizar esta orden")
            # Los aprendices no pueden cambiar ciertos estados
            if orden_data.estado_orden and orden_data.estado_orden.value in ["completada", "procesando"]:
                raise HTTPException(status_code=403, detail="No tiene permisos para cambiar a este estado")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if orden_data.estado_orden is not None:
            update_fields.append("estado_orden = %s")
            params.append(orden_data.estado_orden.value)
        
        if orden_data.total is not None:
            update_fields.append("total = %s")
            params.append(orden_data.total)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(orden_id)
        
        execute_query(
            f"UPDATE ordenes SET {', '.join(update_fields)} WHERE id_orden = %s",
            params
        )
        
        # Obtener la orden actualizada
        orden = execute_query(
            """SELECT o.*, 
                      u.nombre as usuario_nombre, u.documento as usuario_documento,
                      p.nombre as proveedor_nombre
               FROM ordenes o
               JOIN usuarios u ON o.id_usuario = u.id
               LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
               WHERE o.id_orden = %s""",
            (orden_id,),
            fetch_one=True
        )
        
        return orden
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar orden: {str(e)}")

@router.delete("/{orden_id}", response_model=MessageResponse)
async def delete_orden(
    orden_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar orden"""
    try:
        # Verificar si la orden existe
        existing = execute_query(
            "SELECT id_usuario, estado_orden FROM ordenes WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        # Verificar permisos
        if current_user.rol == "aprendiz":
            if existing['id_usuario'] != current_user.id:
                raise HTTPException(status_code=403, detail="No tiene permisos para eliminar esta orden")
            if existing['estado_orden'] != "pendiente":
                raise HTTPException(status_code=403, detail="Solo se pueden eliminar órdenes pendientes")
        elif current_user.rol == "inspector":
            if existing['estado_orden'] in ["procesando", "completada"]:
                raise HTTPException(status_code=403, detail="No se pueden eliminar órdenes en proceso o completadas")
        
        # Solo instructores pueden eliminar cualquier orden
        
        # Eliminar detalles primero (cascade delete debería manejar esto)
        execute_query(
            "DELETE FROM ordenes_detalles WHERE id_orden = %s",
            (orden_id,)
        )
        
        # Eliminar orden
        execute_query(
            "DELETE FROM ordenes WHERE id_orden = %s",
            (orden_id,)
        )
        
        return MessageResponse(
            message="Orden eliminada exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar orden: {str(e)}")

# ==================== RUTAS PARA DETALLES DE ÓRDENES ====================

@router.post("/{orden_id}/detalles", response_model=dict)
async def add_detalle_orden(
    orden_id: int,
    detalle_data: OrdenDetalleCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Agregar detalle a una orden"""
    try:
        # Verificar que la orden existe y permisos
        orden = execute_query(
            "SELECT id_usuario, estado_orden FROM ordenes WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        if current_user.rol == "aprendiz" and orden['id_usuario'] != current_user.id:
            raise HTTPException(status_code=403, detail="No tiene permisos para modificar esta orden")
        
        if orden['estado_orden'] in ["completada", "cancelada"]:
            raise HTTPException(status_code=400, detail="No se pueden agregar detalles a órdenes completadas o canceladas")
        
        # Verificar que el producto existe
        producto = execute_query(
            "SELECT id, nombre FROM productos WHERE id = %s AND activo = TRUE",
            (detalle_data.id_producto,),
            fetch_one=True
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="Producto no encontrado o inactivo")
        
        # Verificar que el usuario existe
        usuario = execute_query(
            "SELECT id FROM usuarios WHERE id = %s",
            (detalle_data.id_usuario,),
            fetch_one=True
        )
        
        if not usuario:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Insertar detalle
        detalle_id = execute_query(
            """INSERT INTO ordenes_detalles (id_orden, id_producto, id_usuario, cantidad, precio)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                orden_id,
                detalle_data.id_producto,
                detalle_data.id_usuario,
                detalle_data.cantidad,
                detalle_data.precio
            ),
            return_id=True
        )
        
        # Recalcular total de la orden
        total_orden = execute_query(
            "SELECT SUM(cantidad * precio) as total FROM ordenes_detalles WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        execute_query(
            "UPDATE ordenes SET total = %s WHERE id_orden = %s",
            (total_orden['total'], orden_id)
        )
        
        # Obtener el detalle creado
        detalle = execute_query(
            """SELECT od.*, 
                      pr.nombre as producto_nombre, pr.codigo as producto_codigo
               FROM ordenes_detalles od
               JOIN productos pr ON od.id_producto = pr.id
               WHERE od.id_detalle = %s""",
            (detalle_id,),
            fetch_one=True
        )
        
        return detalle
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al agregar detalle: {str(e)}")

@router.put("/{orden_id}/detalles/{detalle_id}", response_model=dict)
async def update_detalle_orden(
    orden_id: int,
    detalle_id: int,
    detalle_data: OrdenDetalleUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar detalle de orden"""
    try:
        # Verificar permisos en la orden
        orden = execute_query(
            "SELECT id_usuario, estado_orden FROM ordenes WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        if current_user.rol == "aprendiz" and orden['id_usuario'] != current_user.id:
            raise HTTPException(status_code=403, detail="No tiene permisos para modificar esta orden")
        
        if orden['estado_orden'] in ["completada", "cancelada"]:
            raise HTTPException(status_code=400, detail="No se pueden modificar detalles de órdenes completadas o canceladas")
        
        # Verificar que el detalle existe y pertenece a la orden
        existing = execute_query(
            "SELECT id_detalle FROM ordenes_detalles WHERE id_detalle = %s AND id_orden = %s",
            (detalle_id, orden_id),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Detalle no encontrado en esta orden")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if detalle_data.cantidad is not None:
            update_fields.append("cantidad = %s")
            params.append(detalle_data.cantidad)
        
        if detalle_data.precio is not None:
            update_fields.append("precio = %s")
            params.append(detalle_data.precio)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(detalle_id)
        
        execute_query(
            f"UPDATE ordenes_detalles SET {', '.join(update_fields)} WHERE id_detalle = %s",
            params
        )
        
        # Recalcular total de la orden
        total_orden = execute_query(
            "SELECT SUM(cantidad * precio) as total FROM ordenes_detalles WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        execute_query(
            "UPDATE ordenes SET total = %s WHERE id_orden = %s",
            (total_orden['total'], orden_id)
        )
        
        # Obtener el detalle actualizado
        detalle = execute_query(
            """SELECT od.*, 
                      pr.nombre as producto_nombre, pr.codigo as producto_codigo
               FROM ordenes_detalles od
               JOIN productos pr ON od.id_producto = pr.id
               WHERE od.id_detalle = %s""",
            (detalle_id,),
            fetch_one=True
        )
        
        return detalle
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar detalle: {str(e)}")

@router.delete("/{orden_id}/detalles/{detalle_id}", response_model=MessageResponse)
async def delete_detalle_orden(
    orden_id: int,
    detalle_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar detalle de orden"""
    try:
        # Verificar permisos
        orden = execute_query(
            "SELECT id_usuario, estado_orden FROM ordenes WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        if not orden:
            raise HTTPException(status_code=404, detail="Orden no encontrada")
        
        if current_user.rol == "aprendiz" and orden['id_usuario'] != current_user.id:
            raise HTTPException(status_code=403, detail="No tiene permisos para modificar esta orden")
        
        if orden['estado_orden'] in ["completada", "cancelada"]:
            raise HTTPException(status_code=400, detail="No se pueden eliminar detalles de órdenes completadas o canceladas")
        
        # Verificar que el detalle existe
        existing = execute_query(
            "SELECT id_detalle FROM ordenes_detalles WHERE id_detalle = %s AND id_orden = %s",
            (detalle_id, orden_id),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Detalle no encontrado en esta orden")
        
        # Eliminar detalle
        execute_query(
            "DELETE FROM ordenes_detalles WHERE id_detalle = %s",
            (detalle_id,)
        )
        
        # Recalcular total de la orden
        total_orden = execute_query(
            "SELECT COALESCE(SUM(cantidad * precio), 0) as total FROM ordenes_detalles WHERE id_orden = %s",
            (orden_id,),
            fetch_one=True
        )
        
        execute_query(
            "UPDATE ordenes SET total = %s WHERE id_orden = %s",
            (total_orden['total'], orden_id)
        )
        
        return MessageResponse(
            message="Detalle eliminado exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar detalle: {str(e)}")

# ==================== RUTAS DE ESTADÍSTICAS Y REPORTES ====================

@router.get("/estadisticas/resumen", response_model=dict)
async def get_estadisticas_ordenes(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener estadísticas generales de órdenes"""
    try:
        # Filtro por usuario si es aprendiz
        user_filter = ""
        params = []
        if current_user.rol == "aprendiz":
            user_filter = "WHERE id_usuario = %s"
            params.append(current_user.id)
        
        estadisticas = execute_query(
            f"""SELECT 
                COUNT(*) as total_ordenes,
                COUNT(CASE WHEN estado_orden = 'pendiente' THEN 1 END) as ordenes_pendientes,
                COUNT(CASE WHEN estado_orden = 'procesando' THEN 1 END) as ordenes_procesando,
                COUNT(CASE WHEN estado_orden = 'completada' THEN 1 END) as ordenes_completadas,
                COUNT(CASE WHEN estado_orden = 'cancelada' THEN 1 END) as ordenes_canceladas,
                COALESCE(SUM(total), 0) as valor_total_ordenes,
                COALESCE(AVG(total), 0) as valor_promedio_orden
               FROM ordenes {user_filter}""",
            params,
            fetch_one=True
        )
        
        return estadisticas
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")

@router.get("/estados/", response_model=List[str])
async def get_estados_orden(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener estados de orden disponibles"""
    return [estado.value for estado in EstadoOrden]
