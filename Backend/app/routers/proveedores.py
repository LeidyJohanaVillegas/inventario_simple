from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from ..models import (
    Proveedor, ProveedorCreate, ProveedorUpdate, ProveedorResponse,
    ProductoResponse, OrdenResponse, MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[ProveedorResponse])
async def get_proveedores(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    nombre: Optional[str] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de proveedores"""
    try:
        # Construir consulta base
        query = "SELECT * FROM proveedores"
        conditions = []
        params = []
        
        if nombre:
            conditions.append("nombre LIKE %s")
            params.append(f"%{nombre}%")
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY nombre LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        proveedores = execute_query(query, params, fetch_all=True)
        return proveedores
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener proveedores: {str(e)}")

@router.get("/{proveedor_id}", response_model=ProveedorResponse)
async def get_proveedor(
    proveedor_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener proveedor específico"""
    try:
        proveedor = execute_query(
            "SELECT * FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not proveedor:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        return proveedor
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener proveedor: {str(e)}")

@router.post("/", response_model=ProveedorResponse)
async def create_proveedor(
    proveedor_data: ProveedorCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nuevo proveedor"""
    try:
        # Verificar permisos (solo instructores e inspectores pueden crear proveedores)
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para crear proveedores")
        
        # Verificar si el nombre ya existe
        existing = execute_query(
            "SELECT id_proveedor FROM proveedores WHERE nombre = %s",
            (proveedor_data.nombre,),
            fetch_one=True
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="Ya existe un proveedor con ese nombre")
        
        # Verificar email único si se proporciona
        if proveedor_data.email:
            existing_email = execute_query(
                "SELECT id_proveedor FROM proveedores WHERE email = %s",
                (proveedor_data.email,),
                fetch_one=True
            )
            
            if existing_email:
                raise HTTPException(status_code=400, detail="Ya existe un proveedor con ese email")
        
        # Insertar nuevo proveedor
        proveedor_id = execute_query(
            """INSERT INTO proveedores (nombre, telefono, email, direccion)
               VALUES (%s, %s, %s, %s)""",
            (
                proveedor_data.nombre,
                proveedor_data.telefono,
                proveedor_data.email,
                proveedor_data.direccion
            ),
            return_id=True
        )
        
        # Obtener el proveedor creado
        proveedor = execute_query(
            "SELECT * FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        return proveedor
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear proveedor: {str(e)}")

@router.put("/{proveedor_id}", response_model=ProveedorResponse)
async def update_proveedor(
    proveedor_id: int,
    proveedor_data: ProveedorUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar proveedor"""
    try:
        # Verificar permisos
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para actualizar proveedores")
        
        # Verificar si el proveedor existe
        existing = execute_query(
            "SELECT id_proveedor FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if proveedor_data.nombre is not None:
            # Verificar que el nuevo nombre no exista en otro proveedor
            existing_nombre = execute_query(
                "SELECT id_proveedor FROM proveedores WHERE nombre = %s AND id_proveedor != %s",
                (proveedor_data.nombre, proveedor_id),
                fetch_one=True
            )
            if existing_nombre:
                raise HTTPException(status_code=400, detail="Ya existe otro proveedor con ese nombre")
            
            update_fields.append("nombre = %s")
            params.append(proveedor_data.nombre)
        
        if proveedor_data.telefono is not None:
            update_fields.append("telefono = %s")
            params.append(proveedor_data.telefono)
        
        if proveedor_data.email is not None:
            # Verificar email único si se proporciona
            if proveedor_data.email:
                existing_email = execute_query(
                    "SELECT id_proveedor FROM proveedores WHERE email = %s AND id_proveedor != %s",
                    (proveedor_data.email, proveedor_id),
                    fetch_one=True
                )
                if existing_email:
                    raise HTTPException(status_code=400, detail="Ya existe otro proveedor con ese email")
            
            update_fields.append("email = %s")
            params.append(proveedor_data.email)
        
        if proveedor_data.direccion is not None:
            update_fields.append("direccion = %s")
            params.append(proveedor_data.direccion)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(proveedor_id)
        
        execute_query(
            f"UPDATE proveedores SET {', '.join(update_fields)} WHERE id_proveedor = %s",
            params
        )
        
        # Obtener el proveedor actualizado
        proveedor = execute_query(
            "SELECT * FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        return proveedor
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar proveedor: {str(e)}")

@router.delete("/{proveedor_id}", response_model=MessageResponse)
async def delete_proveedor(
    proveedor_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar proveedor"""
    try:
        # Verificar permisos (solo instructores pueden eliminar)
        if current_user.rol != "instructor":
            raise HTTPException(status_code=403, detail="Solo los instructores pueden eliminar proveedores")
        
        # Verificar si el proveedor existe
        existing = execute_query(
            "SELECT id_proveedor FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Verificar si tiene productos asociados
        productos_asociados = execute_query(
            "SELECT COUNT(*) as count FROM productos WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if productos_asociados['count'] > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"No se puede eliminar el proveedor porque tiene {productos_asociados['count']} productos asociados"
            )
        
        # Verificar si tiene órdenes asociadas
        ordenes_asociadas = execute_query(
            "SELECT COUNT(*) as count FROM ordenes WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if ordenes_asociadas['count'] > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"No se puede eliminar el proveedor porque tiene {ordenes_asociadas['count']} órdenes asociadas"
            )
        
        # Eliminar proveedor
        execute_query(
            "DELETE FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,)
        )
        
        return MessageResponse(
            message="Proveedor eliminado exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar proveedor: {str(e)}")

@router.get("/{proveedor_id}/productos", response_model=List[ProductoResponse])
async def get_productos_proveedor(
    proveedor_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener todos los productos de un proveedor específico"""
    try:
        # Verificar si el proveedor existe
        proveedor = execute_query(
            "SELECT id_proveedor FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not proveedor:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Obtener productos del proveedor
        productos = execute_query(
            """SELECT p.*, 
                      COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
               FROM productos p
               LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
               WHERE p.id_proveedor = %s AND p.activo = TRUE
               GROUP BY p.id
               ORDER BY p.nombre""",
            (proveedor_id,),
            fetch_all=True
        )
        
        return productos
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos del proveedor: {str(e)}")

@router.get("/{proveedor_id}/ordenes", response_model=List[dict])
async def get_ordenes_proveedor(
    proveedor_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener todas las órdenes de un proveedor específico"""
    try:
        # Verificar si el proveedor existe
        proveedor = execute_query(
            "SELECT id_proveedor FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not proveedor:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Obtener órdenes del proveedor
        ordenes = execute_query(
            """SELECT o.*, u.nombre as usuario_nombre, u.documento as usuario_documento
               FROM ordenes o
               JOIN usuarios u ON o.id_usuario = u.id
               WHERE o.id_proveedor = %s
               ORDER BY o.fecha_orden DESC""",
            (proveedor_id,),
            fetch_all=True
        )
        
        return ordenes
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener órdenes del proveedor: {str(e)}")

@router.get("/{proveedor_id}/estadisticas", response_model=dict)
async def get_estadisticas_proveedor(
    proveedor_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener estadísticas de un proveedor"""
    try:
        # Verificar si el proveedor existe
        proveedor = execute_query(
            "SELECT nombre FROM proveedores WHERE id_proveedor = %s",
            (proveedor_id,),
            fetch_one=True
        )
        
        if not proveedor:
            raise HTTPException(status_code=404, detail="Proveedor no encontrado")
        
        # Estadísticas de productos
        stats_productos = execute_query(
            """SELECT 
                COUNT(*) as total_productos,
                COUNT(CASE WHEN activo = TRUE THEN 1 END) as productos_activos
               FROM productos 
               WHERE id_proveedor = %s""",
            (proveedor_id,),
            fetch_one=True
        )
        
        # Estadísticas de órdenes
        stats_ordenes = execute_query(
            """SELECT 
                COUNT(*) as total_ordenes,
                COUNT(CASE WHEN estado_orden = 'pendiente' THEN 1 END) as ordenes_pendientes,
                COUNT(CASE WHEN estado_orden = 'completada' THEN 1 END) as ordenes_completadas,
                COALESCE(SUM(total), 0) as valor_total_ordenes
               FROM ordenes 
               WHERE id_proveedor = %s""",
            (proveedor_id,),
            fetch_one=True
        )
        
        return {
            "proveedor_nombre": proveedor['nombre'],
            "productos": {
                "total": stats_productos['total_productos'],
                "activos": stats_productos['productos_activos']
            },
            "ordenes": {
                "total": stats_ordenes['total_ordenes'],
                "pendientes": stats_ordenes['ordenes_pendientes'],
                "completadas": stats_ordenes['ordenes_completadas'],
                "valor_total": float(stats_ordenes['valor_total_ordenes'])
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")
