from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from ..models import (
    Alerta, AlertaCreate, AlertaUpdate, AlertaConDetalles,
    MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[Alerta])
async def get_alertas(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    tipo: Optional[str] = Query(None),
    nivel: Optional[str] = Query(None),
    atendida: Optional[bool] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de alertas"""
    try:
        # Construir consulta base
        query = "SELECT * FROM alertas"
        
        conditions = []
        params = []
        
        if tipo:
            conditions.append("tipo = %s")
            params.append(tipo)
        
        if nivel:
            conditions.append("nivel = %s")
            params.append(nivel)
        
        if atendida is not None:
            conditions.append("atendida = %s")
            params.append(atendida)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY fecha_creacion DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        alertas = execute_query(query, params, fetch_all=True)
        return alertas
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener alertas: {str(e)}")

@router.get("/{alerta_id}", response_model=AlertaConDetalles)
async def get_alerta(
    alerta_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener alerta específica"""
    try:
        alerta = execute_query(
            """SELECT a.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                      l.numero_lote as lote_numero
               FROM alertas a
               LEFT JOIN productos p ON a.producto_id = p.id
               LEFT JOIN lotes l ON a.lote_id = l.id
               WHERE a.id = %s""",
            (alerta_id,),
            fetch_one=True
        )
        
        if not alerta:
            raise HTTPException(status_code=404, detail="Alerta no encontrada")
        
        # Transformar resultado
        alerta_data = {
            'id': alerta['id'],
            'tipo': alerta['tipo'],
            'producto_id': alerta['producto_id'],
            'lote_id': alerta['lote_id'],
            'mensaje': alerta['mensaje'],
            'nivel': alerta['nivel'],
            'atendida': alerta['atendida'],
            'fecha_creacion': alerta['fecha_creacion'],
            'fecha_atencion': alerta['fecha_atencion']
        }
        
        # Agregar información del producto si existe
        if alerta['producto_id']:
            alerta_data['producto'] = {
                'id': alerta['producto_id'],
                'codigo': alerta['producto_codigo'],
                'nombre': alerta['producto_nombre']
            }
        
        # Agregar información del lote si existe
        if alerta['lote_id']:
            alerta_data['lote'] = {
                'id': alerta['lote_id'],
                'numero_lote': alerta['lote_numero']
            }
        
        return alerta_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener alerta: {str(e)}")

@router.post("/", response_model=Alerta)
async def create_alerta(
    alerta_data: AlertaCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nueva alerta"""
    try:
        # Verificar que al menos uno de producto_id o lote_id esté presente
        if not alerta_data.producto_id and not alerta_data.lote_id:
            raise HTTPException(status_code=400, detail="Debe especificar al menos un producto o lote")
        
        # Verificar que el producto existe (si se especifica)
        if alerta_data.producto_id:
            producto = execute_query(
                "SELECT id FROM productos WHERE id = %s AND activo = TRUE",
                (alerta_data.producto_id,),
                fetch_one=True
            )
            if not producto:
                raise HTTPException(status_code=404, detail="Producto no encontrado")
        
        # Verificar que el lote existe (si se especifica)
        if alerta_data.lote_id:
            lote = execute_query(
                "SELECT id FROM lotes WHERE id = %s AND activo = TRUE",
                (alerta_data.lote_id,),
                fetch_one=True
            )
            if not lote:
                raise HTTPException(status_code=404, detail="Lote no encontrado")
        
        # Insertar nueva alerta
        alerta_id = execute_query(
            """INSERT INTO alertas (tipo, producto_id, lote_id, mensaje, nivel)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                alerta_data.tipo,
                alerta_data.producto_id,
                alerta_data.lote_id,
                alerta_data.mensaje,
                alerta_data.nivel
            )
        )
        
        # Obtener la alerta creada
        alerta = execute_query(
            "SELECT * FROM alertas WHERE id = %s",
            (alerta_id,),
            fetch_one=True
        )
        
        return alerta
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear alerta: {str(e)}")

@router.put("/{alerta_id}", response_model=Alerta)
async def update_alerta(
    alerta_id: int,
    alerta_data: AlertaUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar alerta"""
    try:
        # Verificar si la alerta existe
        existing = execute_query(
            "SELECT id FROM alertas WHERE id = %s",
            (alerta_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Alerta no encontrada")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if alerta_data.atendida is not None:
            update_fields.append("atendida = %s")
            params.append(alerta_data.atendida)
            
            if alerta_data.atendida:
                update_fields.append("fecha_atencion = %s")
                params.append(datetime.now())
        
        if alerta_data.fecha_atencion is not None:
            update_fields.append("fecha_atencion = %s")
            params.append(alerta_data.fecha_atencion)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(alerta_id)
        
        execute_query(
            f"UPDATE alertas SET {', '.join(update_fields)} WHERE id = %s",
            params
        )
        
        # Obtener la alerta actualizada
        alerta = execute_query(
            "SELECT * FROM alertas WHERE id = %s",
            (alerta_id,),
            fetch_one=True
        )
        
        return alerta
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar alerta: {str(e)}")

@router.get("/con-detalles/", response_model=List[AlertaConDetalles])
async def get_alertas_con_detalles(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener alertas con detalles de productos y lotes"""
    try:
        alertas = execute_query(
            """SELECT a.*, p.codigo as producto_codigo, p.nombre as producto_nombre,
                      l.numero_lote as lote_numero
               FROM alertas a
               LEFT JOIN productos p ON a.producto_id = p.id
               LEFT JOIN lotes l ON a.lote_id = l.id
               ORDER BY a.fecha_creacion DESC""",
            fetch_all=True
        )
        
        # Transformar resultados
        alertas_con_detalles = []
        for alerta in alertas:
            alerta_data = {
                'id': alerta['id'],
                'tipo': alerta['tipo'],
                'producto_id': alerta['producto_id'],
                'lote_id': alerta['lote_id'],
                'mensaje': alerta['mensaje'],
                'nivel': alerta['nivel'],
                'atendida': alerta['atendida'],
                'fecha_creacion': alerta['fecha_creacion'],
                'fecha_atencion': alerta['fecha_atencion']
            }
            
            # Agregar información del producto si existe
            if alerta['producto_id']:
                alerta_data['producto'] = {
                    'id': alerta['producto_id'],
                    'codigo': alerta['producto_codigo'],
                    'nombre': alerta['producto_nombre']
                }
            
            # Agregar información del lote si existe
            if alerta['lote_id']:
                alerta_data['lote'] = {
                    'id': alerta['lote_id'],
                    'numero_lote': alerta['lote_numero']
                }
            
            alertas_con_detalles.append(alerta_data)
        
        return alertas_con_detalles
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener alertas con detalles: {str(e)}")

@router.get("/pendientes/", response_model=List[Alerta])
async def get_alertas_pendientes(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener alertas pendientes"""
    try:
        alertas = execute_query(
            "SELECT * FROM alertas WHERE atendida = FALSE ORDER BY fecha_creacion DESC",
            fetch_all=True
        )
        
        return alertas
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener alertas pendientes: {str(e)}")

@router.put("/{alerta_id}/marcar-atendida", response_model=MessageResponse)
async def marcar_alerta_atendida(
    alerta_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Marcar alerta como atendida"""
    try:
        # Verificar si la alerta existe
        existing = execute_query(
            "SELECT id FROM alertas WHERE id = %s",
            (alerta_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Alerta no encontrada")
        
        # Marcar como atendida
        execute_query(
            "UPDATE alertas SET atendida = TRUE, fecha_atencion = %s WHERE id = %s",
            (datetime.now(), alerta_id)
        )
        
        return MessageResponse(
            message="Alerta marcada como atendida exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al marcar alerta como atendida: {str(e)}")
