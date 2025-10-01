from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from ..models import (
    Producto, ProductoCreate, ProductoUpdate, 
    EstadoStock, ReporteInventario, MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[Producto])
async def get_productos(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    categoria: Optional[str] = Query(None),
    activo: Optional[bool] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de productos"""
    try:
        # Construir consulta base
        query = """
            SELECT p.*, 
                   COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
            FROM productos p
            LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
        """
        
        conditions = []
        params = []
        
        if categoria:
            conditions.append("p.categoria = %s")
            params.append(categoria)
        
        if activo is not None:
            conditions.append("p.activo = %s")
            params.append(activo)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " GROUP BY p.id ORDER BY p.nombre LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        productos = execute_query(query, params, fetch_all=True)
        return productos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener productos: {str(e)}")

@router.get("/{producto_id}", response_model=Producto)
async def get_producto(
    producto_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener producto específico"""
    try:
        producto = execute_query(
            """SELECT p.*, 
                      COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
               FROM productos p
               LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
               WHERE p.id = %s
               GROUP BY p.id""",
            (producto_id,),
            fetch_one=True
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        return producto
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener producto: {str(e)}")

@router.post("/", response_model=Producto)
async def create_producto(
    producto_data: ProductoCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nuevo producto"""
    try:
        # Verificar si el código ya existe
        existing = execute_query(
            "SELECT id FROM productos WHERE codigo = %s",
            (producto_data.codigo,),
            fetch_one=True
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="El código del producto ya existe")
        
        # Insertar nuevo producto
        producto_id = execute_query(
            """INSERT INTO productos (codigo, nombre, descripcion, categoria, 
                                    unidad_medida, stock_minimo, es_material_formacion)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (
                producto_data.codigo,
                producto_data.nombre,
                producto_data.descripcion,
                producto_data.categoria,
                producto_data.unidad_medida,
                producto_data.stock_minimo,
                producto_data.es_material_formacion
            )
        )
        
        # Obtener el producto creado
        producto = execute_query(
            "SELECT * FROM productos WHERE id = %s",
            (producto_id,),
            fetch_one=True
        )
        
        return Producto(**producto, stock_actual=0)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear producto: {str(e)}")

@router.put("/{producto_id}", response_model=Producto)
async def update_producto(
    producto_id: int,
    producto_data: ProductoUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar producto"""
    try:
        # Verificar si el producto existe
        existing = execute_query(
            "SELECT id FROM productos WHERE id = %s",
            (producto_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if producto_data.nombre is not None:
            update_fields.append("nombre = %s")
            params.append(producto_data.nombre)
        
        if producto_data.descripcion is not None:
            update_fields.append("descripcion = %s")
            params.append(producto_data.descripcion)
        
        if producto_data.categoria is not None:
            update_fields.append("categoria = %s")
            params.append(producto_data.categoria)
        
        if producto_data.unidad_medida is not None:
            update_fields.append("unidad_medida = %s")
            params.append(producto_data.unidad_medida)
        
        if producto_data.stock_minimo is not None:
            update_fields.append("stock_minimo = %s")
            params.append(producto_data.stock_minimo)
        
        if producto_data.es_material_formacion is not None:
            update_fields.append("es_material_formacion = %s")
            params.append(producto_data.es_material_formacion)
        
        if producto_data.activo is not None:
            update_fields.append("activo = %s")
            params.append(producto_data.activo)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(producto_id)
        
        execute_query(
            f"UPDATE productos SET {', '.join(update_fields)} WHERE id = %s",
            params
        )
        
        # Obtener el producto actualizado
        producto = execute_query(
            """SELECT p.*, 
                      COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
               FROM productos p
               LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
               WHERE p.id = %s
               GROUP BY p.id""",
            (producto_id,),
            fetch_one=True
        )
        
        return producto
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar producto: {str(e)}")

@router.delete("/{producto_id}", response_model=MessageResponse)
async def delete_producto(
    producto_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar producto (soft delete)"""
    try:
        # Verificar si el producto existe
        existing = execute_query(
            "SELECT id FROM productos WHERE id = %s",
            (producto_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        # Soft delete
        execute_query(
            "UPDATE productos SET activo = FALSE WHERE id = %s",
            (producto_id,)
        )
        
        return MessageResponse(
            message="Producto eliminado exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar producto: {str(e)}")

@router.get("/materiales-formacion/", response_model=List[Producto])
async def get_materiales_formacion(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener materiales de formación"""
    try:
        productos = execute_query(
            """SELECT p.*, 
                      COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
               FROM productos p
               LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
               WHERE p.es_material_formacion = TRUE AND p.activo = TRUE
               GROUP BY p.id
               ORDER BY p.nombre""",
            fetch_all=True
        )
        
        return productos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener materiales de formación: {str(e)}")

@router.get("/estado-stock/", response_model=List[EstadoStock])
async def get_estado_stock(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener estado de stock con semáforo visual"""
    try:
        productos = execute_query(
            """SELECT p.id as producto_id, p.nombre as producto_nombre,
                      COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual,
                      p.stock_minimo
               FROM productos p
               LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
               WHERE p.activo = TRUE
               GROUP BY p.id, p.nombre, p.stock_minimo
               ORDER BY p.nombre""",
            fetch_all=True
        )
        
        estados = []
        for producto in productos:
            stock_actual = producto['stock_actual']
            stock_minimo = producto['stock_minimo']
            
            if stock_actual == 0:
                estado = 'sin_stock'
                color = 'rojo'
            elif stock_actual < stock_minimo:
                estado = 'bajo'
                color = 'amarillo'
            else:
                estado = 'normal'
                color = 'verde'
            
            estados.append(EstadoStock(
                producto_id=producto['producto_id'],
                producto_nombre=producto['producto_nombre'],
                stock_actual=stock_actual,
                stock_minimo=stock_minimo,
                estado=estado,
                color=color
            ))
        
        return estados
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener estado de stock: {str(e)}")

@router.get("/reporte-inventario/", response_model=ReporteInventario)
async def get_reporte_inventario(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener reporte general de inventario"""
    try:
        # Estadísticas de productos
        stats_productos = execute_query(
            """SELECT 
                COUNT(*) as total_productos,
                COUNT(CASE WHEN stock_actual > 0 THEN 1 END) as productos_con_stock,
                COUNT(CASE WHEN stock_actual = 0 THEN 1 END) as productos_sin_stock,
                COUNT(CASE WHEN stock_actual < stock_minimo AND stock_actual > 0 THEN 1 END) as productos_bajo_minimo
               FROM (
                   SELECT p.id, p.stock_minimo,
                          COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
                   FROM productos p
                   LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                   WHERE p.activo = TRUE
                   GROUP BY p.id, p.stock_minimo
               ) as stock_info""",
            fetch_one=True
        )
        
        # Estadísticas de lotes
        stats_lotes = execute_query(
            """SELECT 
                COUNT(*) as total_lotes,
                COUNT(CASE WHEN estado = 'vigente' THEN 1 END) as lotes_vigentes,
                COUNT(CASE WHEN estado = 'proximo_vencer' THEN 1 END) as lotes_proximos_vencer,
                COUNT(CASE WHEN estado = 'vencido' THEN 1 END) as lotes_vencidos
               FROM lotes 
               WHERE activo = TRUE""",
            fetch_one=True
        )
        
        # Valor total del inventario
        valor_total = execute_query(
            """SELECT COALESCE(SUM(l.cantidad_disponible * l.precio_unitario), 0) as valor_total
               FROM lotes l
               WHERE l.activo = TRUE""",
            fetch_one=True
        )
        
        return ReporteInventario(
            total_productos=stats_productos['total_productos'],
            productos_con_stock=stats_productos['productos_con_stock'],
            productos_sin_stock=stats_productos['productos_sin_stock'],
            productos_bajo_minimo=stats_productos['productos_bajo_minimo'],
            total_lotes=stats_lotes['total_lotes'],
            lotes_vigentes=stats_lotes['lotes_vigentes'],
            lotes_proximos_vencer=stats_lotes['lotes_proximos_vencer'],
            lotes_vencidos=stats_lotes['lotes_vencidos'],
            valor_total_inventario=float(valor_total['valor_total'])
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al generar reporte: {str(e)}")
