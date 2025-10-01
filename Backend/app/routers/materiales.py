from fastapi import APIRouter, HTTPException, Depends, Query
from typing import List, Optional
from datetime import datetime

from ..models import (
    Material, MaterialCreate, MaterialUpdate, MaterialResponse,
    MessageResponse, Usuario, UsuarioResponse
)
from ..database import execute_query
from .auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[MaterialResponse])
async def get_materiales(
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    tipo_material: Optional[str] = Query(None),
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener lista de materiales"""
    try:
        # Construir consulta base
        query = "SELECT * FROM materiales"
        conditions = []
        params = []
        
        if tipo_material:
            conditions.append("tipo_material = %s")
            params.append(tipo_material)
        
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        
        query += " ORDER BY nombre LIMIT %s OFFSET %s"
        params.extend([limit, skip])
        
        materiales = execute_query(query, params, fetch_all=True)
        return materiales
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener materiales: {str(e)}")

@router.get("/{material_id}", response_model=MaterialResponse)
async def get_material(
    material_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener material específico"""
    try:
        material = execute_query(
            "SELECT * FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        if not material:
            raise HTTPException(status_code=404, detail="Material no encontrado")
        
        return material
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener material: {str(e)}")

@router.post("/", response_model=MaterialResponse)
async def create_material(
    material_data: MaterialCreate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Crear nuevo material"""
    try:
        # Verificar permisos (solo instructores pueden crear materiales)
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para crear materiales")
        
        # Verificar si el nombre ya existe
        existing = execute_query(
            "SELECT id_material FROM materiales WHERE nombre = %s",
            (material_data.nombre,),
            fetch_one=True
        )
        
        if existing:
            raise HTTPException(status_code=400, detail="Ya existe un material con ese nombre")
        
        # Insertar nuevo material
        material_id = execute_query(
            """INSERT INTO materiales (nombre, tipo_material, description, cantidad, relaciones)
               VALUES (%s, %s, %s, %s, %s)""",
            (
                material_data.nombre,
                material_data.tipo_material.value,
                material_data.description,
                material_data.cantidad,
                material_data.relaciones
            ),
            return_id=True
        )
        
        # Obtener el material creado
        material = execute_query(
            "SELECT * FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        return material
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al crear material: {str(e)}")

@router.put("/{material_id}", response_model=MaterialResponse)
async def update_material(
    material_id: int,
    material_data: MaterialUpdate,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Actualizar material"""
    try:
        # Verificar permisos
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para actualizar materiales")
        
        # Verificar si el material existe
        existing = execute_query(
            "SELECT id_material FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Material no encontrado")
        
        # Construir consulta de actualización
        update_fields = []
        params = []
        
        if material_data.nombre is not None:
            update_fields.append("nombre = %s")
            params.append(material_data.nombre)
        
        if material_data.tipo_material is not None:
            update_fields.append("tipo_material = %s")
            params.append(material_data.tipo_material.value)
        
        if material_data.description is not None:
            update_fields.append("description = %s")
            params.append(material_data.description)
        
        if material_data.cantidad is not None:
            update_fields.append("cantidad = %s")
            params.append(material_data.cantidad)
        
        if material_data.relaciones is not None:
            update_fields.append("relaciones = %s")
            params.append(material_data.relaciones)
        
        if not update_fields:
            raise HTTPException(status_code=400, detail="No hay campos para actualizar")
        
        params.append(material_id)
        
        execute_query(
            f"UPDATE materiales SET {', '.join(update_fields)} WHERE id_material = %s",
            params
        )
        
        # Obtener el material actualizado
        material = execute_query(
            "SELECT * FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        return material
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al actualizar material: {str(e)}")

@router.delete("/{material_id}", response_model=MessageResponse)
async def delete_material(
    material_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Eliminar material"""
    try:
        # Verificar permisos (solo instructores pueden eliminar)
        if current_user.rol != "instructor":
            raise HTTPException(status_code=403, detail="Solo los instructores pueden eliminar materiales")
        
        # Verificar si el material existe
        existing = execute_query(
            "SELECT id_material FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        if not existing:
            raise HTTPException(status_code=404, detail="Material no encontrado")
        
        # Eliminar material
        execute_query(
            "DELETE FROM materiales WHERE id_material = %s",
            (material_id,)
        )
        
        return MessageResponse(
            message="Material eliminado exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al eliminar material: {str(e)}")

@router.get("/{material_id}/usuarios-asignados", response_model=List[UsuarioResponse])
async def get_usuarios_asignados(
    material_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener usuarios asignados a un material específico"""
    try:
        # Verificar si el material existe
        material = execute_query(
            "SELECT relaciones FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        if not material:
            raise HTTPException(status_code=404, detail="Material no encontrado")
        
        # Si no hay relaciones, devolver lista vacía
        if not material['relaciones']:
            return []
        
        # Extraer IDs de usuarios de las relaciones JSON
        import json
        relaciones = json.loads(material['relaciones']) if isinstance(material['relaciones'], str) else material['relaciones']
        
        usuarios_ids = []
        if 'id_usuario' in relaciones and relaciones['id_usuario']:
            usuarios_ids.append(relaciones['id_usuario'])
        
        if not usuarios_ids:
            return []
        
        # Obtener usuarios
        placeholders = ','.join(['%s'] * len(usuarios_ids))
        usuarios = execute_query(
            f"SELECT id, documento, nombre, email, rol, activo FROM usuarios WHERE id IN ({placeholders})",
            usuarios_ids,
            fetch_all=True
        )
        
        return usuarios
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener usuarios asignados: {str(e)}")

@router.post("/{material_id}/asignar-usuario/{usuario_id}", response_model=MessageResponse)
async def asignar_usuario_material(
    material_id: int,
    usuario_id: int,
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Asignar un usuario a un material"""
    try:
        # Verificar permisos
        if current_user.rol not in ["instructor", "inspector"]:
            raise HTTPException(status_code=403, detail="No tiene permisos para asignar usuarios")
        
        # Verificar que existan el material y usuario
        material = execute_query(
            "SELECT relaciones FROM materiales WHERE id_material = %s",
            (material_id,),
            fetch_one=True
        )
        
        if not material:
            raise HTTPException(status_code=404, detail="Material no encontrado")
        
        usuario = execute_query(
            "SELECT id FROM usuarios WHERE id = %s",
            (usuario_id,),
            fetch_one=True
        )
        
        if not usuario:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        
        # Actualizar relaciones
        import json
        relaciones = json.loads(material['relaciones']) if material['relaciones'] else {}
        relaciones['id_usuario'] = str(usuario_id)
        
        execute_query(
            "UPDATE materiales SET relaciones = %s WHERE id_material = %s",
            (json.dumps(relaciones), material_id)
        )
        
        return MessageResponse(
            message="Usuario asignado al material exitosamente",
            success=True
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al asignar usuario: {str(e)}")

@router.get("/tipos/", response_model=List[str])
async def get_tipos_material(
    current_user: UsuarioResponse = Depends(get_current_user)
):
    """Obtener tipos de materiales disponibles"""
    from ..models import TipoMaterial
    return [tipo.value for tipo in TipoMaterial]
