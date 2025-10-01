from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime, date

from ..models import (
    Lote, LoteCreate, LoteUpdate, LoteConProducto,
    MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[LoteConProducto])
async def get_lotes(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    producto_id: Optional[int] = Query(None),
    estado: Optional[str] = Query(None),
    activo: Optional[bool] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de lotes"""
    try:
        # Construir consulta base
        query = """
            SELECT l.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                   p.descripcion as producto_descripcion, p.categoria as producto_categoria,
                   p.unidad_medida as producto_unidad_medida, p.stock_minimo as producto_stock_minimo,
                   p.es_material_formacion as producto_es_material_formacion,
                   p.activo as producto_activo, p.fecha_creacion as producto_fecha_creacion,
                   p.fecha_actualizacion as producto_fecha_actualizacion
            FROM lotes l
            INNER JOIN productos p ON l.producto_id = p.id
        """
        
        conditions = []
        params = []
        
        if producto_id:
            conditions.append("l.producto_id = %s")
            params.append(producto_id)
        
        if estado:
            conditions.append("l.estado = %s")
            params.append(estado)
        
        if activo is not None:
            conditions.append("l.activo = %s")
            params.append(activo)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY l.fecha_vencimiento ASC, l.fecha_ingreso DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        lotes = execute_query(query, params, fetch_all=True)
        
        # Transformar resultados para incluir información del producto
        lotes_con_producto = []
        for lote in lotes:
            producto_data = {
                'id': lote['producto_id'],
                'codigo': lote['producto_codigo'],
                'nombre': lote['producto_nombre'],
                'descripcion': lote['producto_descripcion'],
                'categoria': lote['producto_categoria'],
                'unidad_medida': lote['producto_unidad_medida'],
                'stock_minimo': lote['producto_stock_minimo'],
                'es_material_formacion': lote['producto_es_material_formacion'],
                'activo': lote['producto_activo'],
                'fecha_creacion': lote['producto_fecha_creacion'],
                'fecha_actualizacion': lote['producto_fecha_actualizacion']
            }
            
            lote_data = {k: v for k, v in lote.items() if not k.startswith('producto_')}
            lote_data['producto'] = producto_data
            
            lotes_con_producto.append(lote_data)
        
        return lotes_con_producto
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener lotes: {str(e)}")

@router.get("/{lote_id}", response_model=LoteConProducto)
async def get_lote(
    lote_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lote específico"""
    try:
        lote = execute_query(
            """SELECT l.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                      p.descripcion as producto_descripcion, p.categoria as producto_categoria,
                      p.unidad_medida as producto_unidad_medida, p.stock_minimo as producto_stock_minimo,
                      p.es_material_formacion as producto_es_material_formacion,
                      p.activo as producto_activo, p.fecha_creacion as producto_fecha_creacion,
                      p.fecha_actualizacion as producto_fecha_actualizacion
               FROM lotes l
               INNER JOIN productos p ON l.producto_id = p.id
               WHERE l.id = %s""",
            (lote_id,),
            fetch_one=True
        )
        
        if not lote:
            raise HTTPException(status_code=404, detail="Lote no encontrado")
        
        # Transformar resultado
        producto_data = {
            'id': lote['producto_id'],
            'codigo': lote['producto_codigo'],
            'nombre': lote['producto_nombre'],
            'descripcion': lote['producto_descripcion'],
            'categoria': lote['producto_categoria'],
            'unidad_medida': lote['producto_unidad_medida'],
            'stock_minimo': lote['producto_stock_minimo'],
            'es_material_formacion': lote['producto_es_material_formacion'],
            'activo': lote['producto_activo'],
            'fecha_creacion': lote['producto_fecha_creacion'],
            'fecha_actualizacion': lote['producto_fecha_actualizacion']
        }
        
        lote_data = {k: v for k, v in lote.items() if not k.startswith('producto_')}
        lote_data['producto'] = producto_data
        
        return lote_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener lote: {str(e)}")

@router.post("/", response_model=Lote)
async def create_lote(
    lote_data: LoteCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nuevo lote"""
    try:
        # Verificar si el producto existe
        producto = execute_query(
            "SELECT id FROM productos WHERE id = %s AND activo = TRUE",
            (lote_data.producto_id,),
            fetch_one=True
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        # Verificar si el número de lote ya existe para este producto
        existing_lote = execute_query(
            "SELECT id FROM lotes WHERE producto_id = %s AND numero_lote = %s",
            (lote_data.producto_id, lote_data.numero_lote),
            fetch_one=True
        )
        
        if existing_lote:
            raise HTTPException(status_code=400, detail="El número de lote ya existe para este producto")
        
        # Insertar nuevo lote
        lote_id = execute_query(
            """INSERT INTO lotes (producto_id, numero_lote, fecha_ingreso, fecha_vencimiento,
                                cantidad_inicial, cantidad_disponible, precio_unitario, 
                                proveedor, observaciones)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                lote_data.producto_id,
                lote_data.numero_lote,
                lote_data.fecha_ingreso,
                lote_data.fecha_vencimiento,
                lote_data.cantidad_inicial,
                lote_data.cantidad_disponible,
                lote_data.precio_unitario,
                lote_data.proveedor,
                lote_data.observaciones
            )
        )
        
        # Obtener el lote creado
        lote = execute_query(
            "SELECT * FROM lotes WHERE id = %s",
            (lote_id,),
            fetch_one=True
        )
        
        return lote
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear lote: {str(e)}")

@router.put("/{lote_id}", response_model=Lote)
async def update_lote(
    lote_id: int,
    lote_data: LoteUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar lote"""
    try:
        # Verificar si el lote existe
        existing = execute_query(
            "SELECT id FROM lotes WHERE id = %s",
            (lote_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Lote no encontrado")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if lote_data.fecha_ingreso is not None:
            update_fields.append("fecha_ingreso = %s")
            params.append(lote_data.fecha_ingreso)
        
        if lote_data.fecha_vencimiento is not None:
            update_fields.append("fecha_vencimiento = %s")
            params.append(lote_data.fecha_vencimiento)
        
        if lote_data.cantidad_inicial is not None:
            update_fields.append("cantidad_inicial = %s")
            params.append(lote_data.cantidad_inicial)
        
        if lote_data.cantidad_disponible is not None:
            update_fields.append("cantidad_disponible = %s")
            params.append(lote_data.cantidad_disponible)
        
        if lote_data.precio_unitario is not None:
            update_fields.append("precio_unitario = %s")
            params.append(lote_data.precio_unitario)
        
        if lote_data.proveedor is not None:
            update_fields.append("proveedor = %s")
            params.append(lote_data.proveedor)
        
        if lote_data.observaciones is not None:
            update_fields.append("observaciones = %s")
            params.append(lote_data.observaciones)
        
        if lote_data.activo is not None:
            update_fields.append("activo = %s")
            params.append(lote_data.activo)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(lote_id)
        
        execute_query(
            f"UPDATE lotes SET {', '.join(update_fields)} WHERE id = %s",
            params
        )
        
        # Obtener el lote actualizado
        lote = execute_query(
            "SELECT * FROM lotes WHERE id = %s",
            (lote_id,),
            fetch_one=True
        )
        
        return lote
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar lote: {str(e)}")

@router.delete("/{lote_id}", response_model=MessageResponse)
async def delete_lote(
    lote_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar lote (soft delete)"""
    try:
        # Verificar si el lote existe
        existing = execute_query(
            "SELECT id FROM lotes WHERE id = %s",
            (lote_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Lote no encontrado")
        
        # Soft delete
        execute_query(
            "UPDATE lotes SET activo = FALSE WHERE id = %s",
            (lote_id,)
        )
        
        return MessageResponse(
            message="Lote eliminado exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar lote: {str(e)}")

@router.get("/con-productos/", response_model=List[LoteConProducto])
async def get_lotes_con_productos(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lotes con información de productos"""
    return await get_lotes(current_user=current_user)

@router.get("/proximos-vencer/", response_model=List[LoteConProducto])
async def get_lotes_proximos_vencer(
    dias: int = Query(30, ge=1, le=365),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lotes próximos a vencer"""
    try:
        lotes = execute_query(
            """SELECT l.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                      p.descripcion as producto_descripcion, p.categoria as producto_categoria,
                      p.unidad_medida as producto_unidad_medida, p.stock_minimo as producto_stock_minimo,
                      p.es_material_formacion as producto_es_material_formacion,
                      p.activo as producto_activo, p.fecha_creacion as producto_fecha_creacion,
                      p.fecha_actualizacion as producto_fecha_actualizacion
               FROM lotes l
               INNER JOIN productos p ON l.producto_id = p.id
               WHERE l.activo = TRUE 
               AND l.fecha_vencimiento IS NOT NULL
               AND l.fecha_vencimiento <= DATE_ADD(CURDATE(), INTERVAL %s DAY)
               AND l.fecha_vencimiento > CURDATE()
               ORDER BY l.fecha_vencimiento ASC""",
            (dias,),
            fetch_all=True
        )
        
        # Transformar resultados
        lotes_con_producto = []
        for lote in lotes:
            producto_data = {
                'id': lote['producto_id'],
                'codigo': lote['producto_codigo'],
                'nombre': lote['producto_nombre'],
                'descripcion': lote['producto_descripcion'],
                'categoria': lote['producto_categoria'],
                'unidad_medida': lote['producto_unidad_medida'],
                'stock_minimo': lote['producto_stock_minimo'],
                'es_material_formacion': lote['producto_es_material_formacion'],
                'activo': lote['producto_activo'],
                'fecha_creacion': lote['producto_fecha_creacion'],
                'fecha_actualizacion': lote['producto_fecha_actualizacion']
            }
            
            lote_data = {k: v for k, v in lote.items() if not k.startswith('producto_')}
            lote_data['producto'] = producto_data
            
            lotes_con_producto.append(lote_data)
        
        return lotes_con_producto
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener lotes próximos a vencer: {str(e)}")

@router.get("/vencidos/", response_model=List[LoteConProducto])
async def get_lotes_vencidos(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lotes vencidos"""
    try:
        lotes = execute_query(
            """SELECT l.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                      p.descripcion as producto_descripcion, p.categoria as producto_categoria,
                      p.unidad_medida as producto_unidad_medida, p.stock_minimo as producto_stock_minimo,
                      p.es_material_formacion as producto_es_material_formacion,
                      p.activo as producto_activo, p.fecha_creacion as producto_fecha_creacion,
                      p.fecha_actualizacion as producto_fecha_actualizacion
               FROM lotes l
               INNER JOIN productos p ON l.producto_id = p.id
               WHERE l.activo = TRUE 
               AND l.fecha_vencimiento IS NOT NULL
               AND l.fecha_vencimiento < CURDATE()
               ORDER BY l.fecha_vencimiento ASC""",
            fetch_all=True
        )
        
        # Transformar resultados
        lotes_con_producto = []
        for lote in lotes:
            producto_data = {
                'id': lote['producto_id'],
                'codigo': lote['producto_codigo'],
                'nombre': lote['producto_nombre'],
                'descripcion': lote['producto_descripcion'],
                'categoria': lote['producto_categoria'],
                'unidad_medida': lote['producto_unidad_medida'],
                'stock_minimo': lote['producto_stock_minimo'],
                'es_material_formacion': lote['producto_es_material_formacion'],
                'activo': lote['producto_activo'],
                'fecha_creacion': lote['producto_fecha_creacion'],
                'fecha_actualizacion': lote['producto_fecha_actualizacion']
            }
            
            lote_data = {k: v for k, v in lote.items() if not k.startswith('producto_')}
            lote_data['producto'] = producto_data
            
            lotes_con_producto.append(lote_data)
        
        return lotes_con_producto
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener lotes vencidos: {str(e)}")

@router.post("/actualizar-estados/", response_model=MessageResponse)
async def actualizar_estados_lotes(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar estados de lotes automáticamente"""
    try:
        # Actualizar estados basado en fechas de vencimiento
        execute_query(
            """UPDATE lotes 
               SET estado = CASE 
                   WHEN fecha_vencimiento IS NULL THEN 'vigente'
                   WHEN fecha_vencimiento < CURDATE() THEN 'vencido'
                   WHEN fecha_vencimiento <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN 'proximo_vencer'
                   ELSE 'vigente'
               END
               WHERE activo = TRUE""",
        )
        
        return MessageResponse(
            message="Estados de lotes actualizados exitosamente",
            success=True
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar estados: {str(e)}")
