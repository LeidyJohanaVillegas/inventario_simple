from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime, date

from ..models import (
    ConfiguracionProducto, ConfiguracionProductoCreate, ConfiguracionProductoUpdate, ConfiguracionProductoResponse,
    TipoConfig, Color, MessageResponse, ProductoResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[dict])
async def get_configuraciones(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    producto_id: Optional[int] = Query(None),
    tipo_config: Optional[TipoConfig] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de configuraciones de productos"""
    try:
        # Construir consulta base
        query = """
            SELECT cp.*, 
                   p.nombre as producto_nombre, p.codigo as producto_codigo,
                   p.categoria as producto_categoria
            FROM configuraciones_producto cp
            JOIN productos p ON cp.id_producto = p.id
        """
        conditions = []
        params = []
        
        if producto_id:
            conditions.append("cp.id_producto = %s")
            params.append(producto_id)
        
        if tipo_config:
            conditions.append("cp.tipo_config = %s")
            params.append(tipo_config.value)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY p.nombre, cp.tipo_config LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        configuraciones = execute_query(query, params, fetch_all=True)
        return configuraciones
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener configuraciones: {str(e)}")

@router.get("/{config_id}", response_model=dict)
async def get_configuracion(
    config_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener configuración específica"""
    try:
        configuracion = execute_query(
            """SELECT cp.*, 
                      p.nombre as producto_nombre, p.codigo as producto_codigo,
                      p.categoria as producto_categoria, p.stock_minimo as producto_stock_minimo
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_config_producto = %s""",
            (config_id,),
            fetch_one=True
        )
        
        if not configuracion:
            raise HTTPException(status_code=404, detail="Configuración no encontrada")
        
        return configuracion
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener configuración: {str(e)}")

@router.post("/", response_model=dict)
async def create_configuracion(
    config_data: ConfiguracionProductoCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nueva configuración de producto"""
    try:
        # Verificar permisos (solo instructores e inspectores)
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para crear configuraciones")
        
        # Verificar que el producto existe
        producto = execute_query(
            "SELECT id, nombre FROM productos WHERE id = %s AND activo = TRUE",
            (config_data.id_producto,),
            fetch_one=True
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="Producto no encontrado o inactivo")
        
        # Verificar que no exista ya una configuración del mismo tipo para este producto
        existing = execute_query(
            "SELECT id_config_producto FROM configuraciones_producto WHERE id_producto = %s AND tipo_config = %s",
            (config_data.id_producto, config_data.tipo_config.value),
            fetch_one=True
        )
        
        if existing:
            raise HTTPException(
                status_code=400, 
                detail=f"Ya existe una configuración de tipo '{config_data.tipo_config.value}' para este producto"
            )
        
        # Validar valores según el tipo de configuración
        if config_data.tipo_config == TipoConfig.STOCK:
            if config_data.valor_min is None:
                raise HTTPException(status_code=400, detail="valor_min es requerido para configuraciones de stock")
            if config_data.valor_min < 0:
                raise HTTPException(status_code=400, detail="valor_min no puede ser negativo")
        
        # Insertar nueva configuración
        config_id = execute_query(
            """INSERT INTO configuraciones_producto (id_producto, tipo_config, color, valor_min, valor_max)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                config_data.id_producto,
                config_data.tipo_config.value,
                config_data.color.value,
                config_data.valor_min,
                config_data.valor_max
            ),
            return_id=True
        )
        
        # Obtener la configuración creada
        configuracion = execute_query(
            """SELECT cp.*, 
                      p.nombre as producto_nombre, p.codigo as producto_codigo
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_config_producto = %s""",
            (config_id,),
            fetch_one=True
        )
        
        return configuracion
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear configuración: {str(e)}")

@router.put("/{config_id}", response_model=dict)
async def update_configuracion(
    config_id: int,
    config_data: ConfiguracionProductoUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar configuración de producto"""
    try:
        # Verificar permisos
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para actualizar configuraciones")
        
        # Verificar si la configuración existe
        existing = execute_query(
            "SELECT id_producto, tipo_config FROM configuraciones_producto WHERE id_config_producto = %s",
            (config_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Configuración no encontrada")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if config_data.tipo_config is not None:
            # Verificar que no exista otra configuración del mismo tipo para el mismo producto
            conflicto = execute_query(
                """SELECT id_config_producto FROM configuraciones_producto 
                   WHERE id_producto = %s AND tipo_config = %s AND id_config_producto != %s""",
                (existing['id_producto'], config_data.tipo_config.value, config_id),
                fetch_one=True
            )
            
            if conflicto:
                raise HTTPException(
                    status_code=400,
                    detail=f"Ya existe otra configuración de tipo '{config_data.tipo_config.value}' para este producto"
                )
            
            update_fields.append("tipo_config = %s")
            params.append(config_data.tipo_config.value)
        
        if config_data.color is not None:
            update_fields.append("color = %s")
            params.append(config_data.color.value)
        
        if config_data.valor_min is not None:
            if config_data.valor_min < 0:
                raise HTTPException(status_code=400, detail="valor_min no puede ser negativo")
            update_fields.append("valor_min = %s")
            params.append(config_data.valor_min)
        
        if config_data.valor_max is not None:
            update_fields.append("valor_max = %s")
            params.append(config_data.valor_max)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(config_id)
        
        execute_query(
            f"UPDATE configuraciones_producto SET {', '.join(update_fields)} WHERE id_config_producto = %s",
            params
        )
        
        # Obtener la configuración actualizada
        configuracion = execute_query(
            """SELECT cp.*, 
                      p.nombre as producto_nombre, p.codigo as producto_codigo
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_config_producto = %s""",
            (config_id,),
            fetch_one=True
        )
        
        return configuracion
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar configuración: {str(e)}")

@router.delete("/{config_id}", response_model=MessageResponse)
async def delete_configuracion(
    config_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar configuración de producto"""
    try:
        # Verificar permisos (solo instructores pueden eliminar)
        if current_user.rol != "instructor":
            raise HTTPException(status_code=403, detail="Solo los instructores pueden eliminar configuraciones")
        
        # Verificar si la configuración existe
        existing = execute_query(
            "SELECT id_config_producto FROM configuraciones_producto WHERE id_config_producto = %s",
            (config_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Configuración no encontrada")
        
        # Verificar si hay alertas asociadas
        alertas_asociadas = execute_query(
            "SELECT COUNT(*) as count FROM alertas WHERE id_config_producto = %s",
            (config_id,),
            fetch_one=True
        )
        
        if alertas_asociadas['count'] > 0:
            raise HTTPException(
                status_code=400,
                detail=f"No se puede eliminar la configuración porque tiene {alertas_asociadas['count']} alertas asociadas"
            )
        
        # Eliminar configuración
        execute_query(
            "DELETE FROM configuraciones_producto WHERE id_config_producto = %s",
            (config_id,)
        )
        
        return MessageResponse(
            message="Configuración eliminada exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar configuración: {str(e)}")

@router.post("/{config_id}/evaluar-stock", response_model=dict)
async def evaluar_stock(
    config_id: int,
    stock: int = Query(..., ge=0),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Evaluar stock según la configuración (implementa el método evaluarStock de la documentación)"""
    try:
        # Obtener configuración
        configuracion = execute_query(
            """SELECT cp.*, p.nombre as producto_nombre
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_config_producto = %s AND cp.tipo_config = 'stock'""",
            (config_id,),
            fetch_one=True
        )
        
        if not configuracion:
            raise HTTPException(status_code=404, detail="Configuración de stock no encontrada")
        
        # Evaluar stock
        valor_min = configuracion['valor_min'] or 0
        valor_max = configuracion['valor_max']
        
        if stock == 0:
            estado = "sin_stock"
            color = "rojo"
            mensaje = "Producto sin stock"
        elif stock < valor_min:
            estado = "stock_bajo"
            color = "amarillo"
            mensaje = f"Stock bajo (mínimo: {valor_min})"
        elif valor_max and stock > valor_max:
            estado = "stock_excedido"
            color = "amarillo"
            mensaje = f"Stock excedido (máximo: {valor_max})"
        else:
            estado = "normal"
            color = "verde"
            mensaje = "Stock normal"
        
        return {
            "producto_nombre": configuracion['producto_nombre'],
            "stock_actual": stock,
            "valor_min": valor_min,
            "valor_max": valor_max,
            "estado": estado,
            "color": color,
            "mensaje": mensaje,
            "evaluacion_timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al evaluar stock: {str(e)}")

@router.post("/{config_id}/evaluar-vencimiento", response_model=dict)
async def evaluar_vencimiento(
    config_id: int,
    fecha_vencimiento: date = Query(...),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Evaluar vencimiento según la configuración (implementa el método estaVencido de la documentación)"""
    try:
        # Obtener configuración
        configuracion = execute_query(
            """SELECT cp.*, p.nombre as producto_nombre
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_config_producto = %s AND cp.tipo_config = 'vencimiento'""",
            (config_id,),
            fetch_one=True
        )
        
        if not configuracion:
            raise HTTPException(status_code=404, detail="Configuración de vencimiento no encontrada")
        
        # Evaluar vencimiento
        fecha_actual = date.today()
        dias_restantes = (fecha_vencimiento - fecha_actual).days
        
        valor_min = configuracion['valor_min'] or 30  # Días de advertencia por defecto
        
        if dias_restantes < 0:
            estado = "vencido"
            color = "rojo"
            mensaje = f"Producto vencido hace {abs(dias_restantes)} días"
            esta_vencido = True
        elif dias_restantes <= valor_min:
            estado = "proximo_a_vencer"
            color = "amarillo"
            mensaje = f"Producto próximo a vencer en {dias_restantes} días"
            esta_vencido = False
        else:
            estado = "vigente"
            color = "verde"
            mensaje = f"Producto vigente ({dias_restantes} días restantes)"
            esta_vencido = False
        
        return {
            "producto_nombre": configuracion['producto_nombre'],
            "fecha_vencimiento": fecha_vencimiento.isoformat(),
            "fecha_actual": fecha_actual.isoformat(),
            "dias_restantes": dias_restantes,
            "dias_advertencia": valor_min,
            "esta_vencido": esta_vencido,
            "estado": estado,
            "color": color,
            "mensaje": mensaje,
            "evaluacion_timestamp": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al evaluar vencimiento: {str(e)}")

@router.get("/producto/{producto_id}", response_model=List[dict])
async def get_configuraciones_producto(
    producto_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener todas las configuraciones de un producto específico"""
    try:
        # Verificar que el producto existe
        producto = execute_query(
            "SELECT id, nombre FROM productos WHERE id = %s",
            (producto_id,),
            fetch_one=True
        )
        
        if not producto:
            raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        # Obtener configuraciones
        configuraciones = execute_query(
            """SELECT cp.*, p.nombre as producto_nombre, p.codigo as producto_codigo
               FROM configuraciones_producto cp
               JOIN productos p ON cp.id_producto = p.id
               WHERE cp.id_producto = %s
               ORDER BY cp.tipo_config""",
            (producto_id,),
            fetch_all=True
        )
        
        return configuraciones
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener configuraciones del producto: {str(e)}")

@router.get("/tipos/", response_model=List[str])
async def get_tipos_configuracion(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener tipos de configuración disponibles"""
    return [tipo.value for tipo in TipoConfig]

@router.get("/colores/", response_model=List[str])
async def get_colores_disponibles(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener colores disponibles para configuraciones"""
    return [color.value for color in Color]
