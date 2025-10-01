from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from ..models import (
    Movimiento, MovimientoCreate, MovimientoConDetalles,
    MessageResponse
)
from ..database import execute_query
from .auth import get_current_user, UsuarioResponse

router = APIRouter()

@router.get("/", response_model=List[Movimiento])
async def get_movimientos(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    lote_id: Optional[int] = Query(None),
    usuario_id: Optional[int] = Query(None),
    tipo: Optional[str] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de movimientos"""
    try:
        # Construir consulta base
        query = "SELECT * FROM movimientos"
        
        conditions = []
        params = []
        
        if lote_id:
            conditions.append("lote_id = %s")
            params.append(lote_id)
        
        if usuario_id:
            conditions.append("usuario_id = %s")
            params.append(usuario_id)
        
        if tipo:
            conditions.append("tipo = %s")
            params.append(tipo)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY fecha_movimiento DESC LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        movimientos = execute_query(query, params, fetch_all=True)
        return movimientos
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimientos: {str(e)}")

@router.get("/{movimiento_id}", response_model=MovimientoConDetalles)
async def get_movimiento(
    movimiento_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener movimiento específico"""
    try:
        movimiento = execute_query(
            """SELECT m.*, l.numero_lote, l.fecha_ingreso, l.fecha_vencimiento,
                      l.cantidad_disponible, l.estado, l.precio_unitario,
                      p.codigo as producto_codigo, p.nombre as producto_nombre,
                      u.documento as usuario_documento, u.nombre as usuario_nombre,
                      u.rol as usuario_rol
               FROM movimientos m
               INNER JOIN lotes l ON m.lote_id = l.id
               INNER JOIN productos p ON l.producto_id = p.id
               INNER JOIN usuarios u ON m.usuario_id = u.id
               WHERE m.id = %s""",
            (movimiento_id,),
            fetch_one=True
        )
        
        if not movimiento:
            raise HTTPException(status_code=404, detail="Movimiento no encontrado")
        
        # Transformar resultado
        movimiento_data = {
            'id': movimiento['id'],
            'lote_id': movimiento['lote_id'],
            'usuario_id': movimiento['usuario_id'],
            'tipo': movimiento['tipo'],
            'cantidad': movimiento['cantidad'],
            'motivo': movimiento['motivo'],
            'observaciones': movimiento['observaciones'],
            'fecha_movimiento': movimiento['fecha_movimiento']
        }
        
        # Agregar información del lote
        movimiento_data['lote'] = {
            'id': movimiento['lote_id'],
            'numero_lote': movimiento['numero_lote'],
            'fecha_ingreso': movimiento['fecha_ingreso'],
            'fecha_vencimiento': movimiento['fecha_vencimiento'],
            'cantidad_disponible': movimiento['cantidad_disponible'],
            'estado': movimiento['estado'],
            'precio_unitario': movimiento['precio_unitario']
        }
        
        # Agregar información del usuario
        movimiento_data['usuario'] = {
            'id': movimiento['usuario_id'],
            'documento': movimiento['usuario_documento'],
            'nombre': movimiento['usuario_nombre'],
            'rol': movimiento['usuario_rol']
        }
        
        return movimiento_data
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimiento: {str(e)}")

@router.post("/", response_model=Movimiento)
async def create_movimiento(
    movimiento_data: MovimientoCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nuevo movimiento"""
    try:
        # Verificar si el lote existe
        lote = execute_query(
            "SELECT id, cantidad_disponible FROM lotes WHERE id = %s AND activo = TRUE",
            (movimiento_data.lote_id,),
            fetch_one=True
        )
        
        if not lote:
            raise HTTPException(status_code=404, detail="Lote no encontrado")
        
        # Verificar disponibilidad para salidas
        if movimiento_data.tipo == "salida":
            if lote['cantidad_disponible'] < movimiento_data.cantidad:
                raise HTTPException(
                    status_code=400, 
                    detail=f"No hay suficiente stock. Disponible: {lote['cantidad_disponible']}"
                )
        
        # Insertar nuevo movimiento
        movimiento_id = execute_query(
            """INSERT INTO movimientos (lote_id, usuario_id, tipo, cantidad, motivo, observaciones)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (
                movimiento_data.lote_id,
                current_user.id,
                movimiento_data.tipo,
                movimiento_data.cantidad,
                movimiento_data.motivo,
                movimiento_data.observaciones
            )
        )
        
        # Actualizar cantidad disponible en el lote
        if movimiento_data.tipo == "entrada":
            nueva_cantidad = lote['cantidad_disponible'] + movimiento_data.cantidad
        elif movimiento_data.tipo == "salida":
            nueva_cantidad = lote['cantidad_disponible'] - movimiento_data.cantidad
        else:  # ajuste
            nueva_cantidad = movimiento_data.cantidad
        
        execute_query(
            "UPDATE lotes SET cantidad_disponible = %s WHERE id = %s",
            (nueva_cantidad, movimiento_data.lote_id)
        )
        
        # Obtener el movimiento creado
        movimiento = execute_query(
            "SELECT * FROM movimientos WHERE id = %s",
            (movimiento_id,),
            fetch_one=True
        )
        
        return movimiento
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear movimiento: {str(e)}")

@router.get("/con-detalles/", response_model=List[MovimientoConDetalles])
async def get_movimientos_con_detalles(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener movimientos con detalles de lotes y usuarios"""
    try:
        movimientos = execute_query(
            """SELECT m.*, l.numero_lote, l.fecha_ingreso, l.fecha_vencimiento,
                      l.cantidad_disponible, l.estado, l.precio_unitario,
                      p.codigo as producto_codigo, p.nombre as producto_nombre,
                      u.documento as usuario_documento, u.nombre as usuario_nombre,
                      u.rol as usuario_rol
               FROM movimientos m
               INNER JOIN lotes l ON m.lote_id = l.id
               INNER JOIN productos p ON l.producto_id = p.id
               INNER JOIN usuarios u ON m.usuario_id = u.id
               ORDER BY m.fecha_movimiento DESC""",
            fetch_all=True
        )
        
        # Transformar resultados
        movimientos_con_detalles = []
        for movimiento in movimientos:
            movimiento_data = {
                'id': movimiento['id'],
                'lote_id': movimiento['lote_id'],
                'usuario_id': movimiento['usuario_id'],
                'tipo': movimiento['tipo'],
                'cantidad': movimiento['cantidad'],
                'motivo': movimiento['motivo'],
                'observaciones': movimiento['observaciones'],
                'fecha_movimiento': movimiento['fecha_movimiento']
            }
            
            # Agregar información del lote
            movimiento_data['lote'] = {
                'id': movimiento['lote_id'],
                'numero_lote': movimiento['numero_lote'],
                'fecha_ingreso': movimiento['fecha_ingreso'],
                'fecha_vencimiento': movimiento['fecha_vencimiento'],
                'cantidad_disponible': movimiento['cantidad_disponible'],
                'estado': movimiento['estado'],
                'precio_unitario': movimiento['precio_unitario']
            }
            
            # Agregar información del usuario
            movimiento_data['usuario'] = {
                'id': movimiento['usuario_id'],
                'documento': movimiento['usuario_documento'],
                'nombre': movimiento['usuario_nombre'],
                'rol': movimiento['usuario_rol']
            }
            
            movimientos_con_detalles.append(movimiento_data)
        
        return movimientos_con_detalles
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimientos con detalles: {str(e)}")

@router.get("/por-usuario/{usuario_id}", response_model=List[MovimientoConDetalles])
async def get_movimientos_por_usuario(
    usuario_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener movimientos por usuario específico"""
    try:
        movimientos = execute_query(
            """SELECT m.*, l.numero_lote, l.fecha_ingreso, l.fecha_vencimiento,
                      l.cantidad_disponible, l.estado, l.precio_unitario,
                      p.codigo as producto_codigo, p.nombre as producto_nombre,
                      u.documento as usuario_documento, u.nombre as usuario_nombre,
                      u.rol as usuario_rol
               FROM movimientos m
               INNER JOIN lotes l ON m.lote_id = l.id
               INNER JOIN productos p ON l.producto_id = p.id
               INNER JOIN usuarios u ON m.usuario_id = u.id
               WHERE m.usuario_id = %s
               ORDER BY m.fecha_movimiento DESC""",
            (usuario_id,),
            fetch_all=True
        )
        
        # Transformar resultados (mismo código que get_movimientos_con_detalles)
        movimientos_con_detalles = []
        for movimiento in movimientos:
            movimiento_data = {
                'id': movimiento['id'],
                'lote_id': movimiento['lote_id'],
                'usuario_id': movimiento['usuario_id'],
                'tipo': movimiento['tipo'],
                'cantidad': movimiento['cantidad'],
                'motivo': movimiento['motivo'],
                'observaciones': movimiento['observaciones'],
                'fecha_movimiento': movimiento['fecha_movimiento']
            }
            
            movimiento_data['lote'] = {
                'id': movimiento['lote_id'],
                'numero_lote': movimiento['numero_lote'],
                'fecha_ingreso': movimiento['fecha_ingreso'],
                'fecha_vencimiento': movimiento['fecha_vencimiento'],
                'cantidad_disponible': movimiento['cantidad_disponible'],
                'estado': movimiento['estado'],
                'precio_unitario': movimiento['precio_unitario']
            }
            
            movimiento_data['usuario'] = {
                'id': movimiento['usuario_id'],
                'documento': movimiento['usuario_documento'],
                'nombre': movimiento['usuario_nombre'],
                'rol': movimiento['usuario_rol']
            }
            
            movimientos_con_detalles.append(movimiento_data)
        
        return movimientos_con_detalles
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimientos por usuario: {str(e)}")

@router.get("/por-tipo/{tipo}", response_model=List[MovimientoConDetalles])
async def get_movimientos_por_tipo(
    tipo: str,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener movimientos por tipo específico"""
    try:
        # Validar tipo
        tipos_validos = ["entrada", "salida", "ajuste"]
        if tipo not in tipos_validos:
            raise HTTPException(status_code=400, detail=f"Tipo inválido. Tipos válidos: {tipos_validos}")
        
        movimientos = execute_query(
            """SELECT m.*, l.numero_lote, l.fecha_ingreso, l.fecha_vencimiento,
                      l.cantidad_disponible, l.estado, l.precio_unitario,
                      p.codigo as producto_codigo, p.nombre as producto_nombre,
                      u.documento as usuario_documento, u.nombre as usuario_nombre,
                      u.rol as usuario_rol
               FROM movimientos m
               INNER JOIN lotes l ON m.lote_id = l.id
               INNER JOIN productos p ON l.producto_id = p.id
               INNER JOIN usuarios u ON m.usuario_id = u.id
               WHERE m.tipo = %s
               ORDER BY m.fecha_movimiento DESC""",
            (tipo,),
            fetch_all=True
        )
        
        # Transformar resultados (mismo código que get_movimientos_con_detalles)
        movimientos_con_detalles = []
        for movimiento in movimientos:
            movimiento_data = {
                'id': movimiento['id'],
                'lote_id': movimiento['lote_id'],
                'usuario_id': movimiento['usuario_id'],
                'tipo': movimiento['tipo'],
                'cantidad': movimiento['cantidad'],
                'motivo': movimiento['motivo'],
                'observaciones': movimiento['observaciones'],
                'fecha_movimiento': movimiento['fecha_movimiento']
            }
            
            movimiento_data['lote'] = {
                'id': movimiento['lote_id'],
                'numero_lote': movimiento['numero_lote'],
                'fecha_ingreso': movimiento['fecha_ingreso'],
                'fecha_vencimiento': movimiento['fecha_vencimiento'],
                'cantidad_disponible': movimiento['cantidad_disponible'],
                'estado': movimiento['estado'],
                'precio_unitario': movimiento['precio_unitario']
            }
            
            movimiento_data['usuario'] = {
                'id': movimiento['usuario_id'],
                'documento': movimiento['usuario_documento'],
                'nombre': movimiento['usuario_nombre'],
                'rol': movimiento['usuario_rol']
            }
            
            movimientos_con_detalles.append(movimiento_data)
        
        return movimientos_con_detalles
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener movimientos por tipo: {str(e)}")
