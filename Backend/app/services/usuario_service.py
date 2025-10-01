"""
Servicio de Usuario con métodos adicionales según la documentación del proyecto
Implementa métodos faltantes de la clase Usuario (Clase --1)
"""

from typing import List, Dict, Any, Optional
from fastapi import HTTPException
from datetime import datetime, date

from ..database import execute_query
from ..auth.security import verify_password, hash_password
from ..models import UsuarioResponse, ProductoResponse, OrdenResponse, MovimientoResponse

class UsuarioService:
    """
    Servicio que implementa los métodos adicionales de la clase Usuario
    según la documentación (Clase --1)
    """
    
    def __init__(self):
        pass
    
    def verify_password(self, user_id: int, password: str) -> bool:
        """
        Verifica si la contraseña ingresada coincide
        Método verifyPassword(pwd: str): bool de la documentación
        """
        try:
            user = execute_query(
                "SELECT password_hash FROM usuarios WHERE id = %s AND activo = TRUE",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                return False
                
            return verify_password(password, user['password_hash'])
            
        except Exception:
            return False
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """
        Permite cambiar la contraseña
        Método changePassword(oldPassword: str, newPassword: str): bool de la documentación
        """
        try:
            # Verificar contraseña actual
            if not self.verify_password(user_id, old_password):
                return False
            
            # Hashear nueva contraseña
            new_hashed = hash_password(new_password)
            
            # Actualizar contraseña
            execute_query(
                "UPDATE usuarios SET password_hash = %s WHERE id = %s",
                (new_hashed, user_id)
            )
            
            return True
            
        except Exception:
            return False
    
    def get_ordenes(self, user_id: int, permisos: str) -> List[Dict[str, Any]]:
        """
        Obtiene las órdenes relacionadas al usuario
        Método getOrdenes(permisos): List<Orden> de la documentación
        """
        try:
            # Obtener información del usuario para verificar rol
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
            # Filtrar órdenes según permisos y rol
            if user['rol'] == 'aprendiz':
                # Los aprendices solo ven sus propias órdenes
                ordenes = execute_query(
                    """SELECT o.*, p.nombre as proveedor_nombre
                       FROM ordenes o
                       LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
                       WHERE o.id_usuario = %s
                       ORDER BY o.fecha_orden DESC""",
                    (user_id,),
                    fetch_all=True
                )
            elif user['rol'] in ['instructor', 'inspector']:
                # Instructores e inspectores ven todas las órdenes
                if permisos == 'all':
                    ordenes = execute_query(
                        """SELECT o.*, p.nombre as proveedor_nombre, u.nombre as usuario_nombre
                           FROM ordenes o
                           LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
                           LEFT JOIN usuarios u ON o.id_usuario = u.id
                           ORDER BY o.fecha_orden DESC""",
                        fetch_all=True
                    )
                else:
                    # Solo órdenes relacionadas con el usuario
                    ordenes = execute_query(
                        """SELECT o.*, p.nombre as proveedor_nombre
                           FROM ordenes o
                           LEFT JOIN proveedores p ON o.id_proveedor = p.id_proveedor
                           WHERE o.id_usuario = %s
                           ORDER BY o.fecha_orden DESC""",
                        (user_id,),
                        fetch_all=True
                    )
            else:
                ordenes = []
            
            return ordenes
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al obtener órdenes: {str(e)}")
    
    def get_movimientos(self, user_id: int, permisos: str) -> List[Dict[str, Any]]:
        """
        Obtiene movimientos vinculados al usuario
        Método getMovimientos(permisos): List<Movimiento> de la documentación
        """
        try:
            # Obtener información del usuario
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                raise HTTPException(status_code=404, detail="Usuario no encontrado")
            
            # Filtrar movimientos según permisos y rol
            if user['rol'] == 'aprendiz':
                # Los aprendices solo ven sus propios movimientos
                movimientos = execute_query(
                    """SELECT m.*, l.numero_lote, p.nombre as producto_nombre, p.codigo as producto_codigo
                       FROM movimientos m
                       JOIN lotes l ON m.lote_id = l.id
                       JOIN productos p ON l.producto_id = p.id
                       WHERE m.usuario_id = %s
                       ORDER BY m.fecha_movimiento DESC""",
                    (user_id,),
                    fetch_all=True
                )
            elif user['rol'] in ['instructor', 'inspector']:
                if permisos == 'all':
                    # Ver todos los movimientos
                    movimientos = execute_query(
                        """SELECT m.*, l.numero_lote, p.nombre as producto_nombre, p.codigo as producto_codigo,
                                  u.nombre as usuario_nombre, u.documento as usuario_documento
                           FROM movimientos m
                           JOIN lotes l ON m.lote_id = l.id
                           JOIN productos p ON l.producto_id = p.id
                           JOIN usuarios u ON m.usuario_id = u.id
                           ORDER BY m.fecha_movimiento DESC""",
                        fetch_all=True
                    )
                else:
                    # Solo movimientos del usuario
                    movimientos = execute_query(
                        """SELECT m.*, l.numero_lote, p.nombre as producto_nombre, p.codigo as producto_codigo
                           FROM movimientos m
                           JOIN lotes l ON m.lote_id = l.id
                           JOIN productos p ON l.producto_id = p.id
                           WHERE m.usuario_id = %s
                           ORDER BY m.fecha_movimiento DESC""",
                        (user_id,),
                        fetch_all=True
                    )
            else:
                movimientos = []
            
            return movimientos
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al obtener movimientos: {str(e)}")
    
    def get_productos_asignados(self, user_id: int) -> List[Dict[str, Any]]:
        """
        Devuelve los productos asignados al usuario
        Método getProductosAsignados(): List<Producto> de la documentación
        """
        try:
            # Buscar productos asignados en materiales donde el usuario está en las relaciones
            productos_materiales = execute_query(
                """SELECT DISTINCT p.*, 'material' as origen
                   FROM productos p
                   JOIN materiales m ON JSON_EXTRACT(m.relaciones, '$.id_usuario') = %s
                   WHERE p.activo = TRUE""",
                (str(user_id),),
                fetch_all=True
            )
            
            # Buscar productos en lotes donde el usuario ha hecho movimientos
            productos_movimientos = execute_query(
                """SELECT DISTINCT p.*, 'movimiento' as origen,
                          COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
                   FROM productos p
                   JOIN lotes l ON p.id = l.producto_id
                   JOIN movimientos m ON l.id = m.lote_id
                   WHERE m.usuario_id = %s AND p.activo = TRUE AND l.activo = TRUE
                   GROUP BY p.id""",
                (user_id,),
                fetch_all=True
            )
            
            # Combinar resultados sin duplicados
            productos_dict = {}
            
            for producto in productos_materiales:
                productos_dict[producto['id']] = producto
            
            for producto in productos_movimientos:
                if producto['id'] not in productos_dict:
                    productos_dict[producto['id']] = producto
                else:
                    # Agregar información de stock si no existe
                    productos_dict[producto['id']]['stock_actual'] = producto.get('stock_actual', 0)
            
            return list(productos_dict.values())
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al obtener productos asignados: {str(e)}")
    
    def puede_crear_producto(self, user_id: int) -> bool:
        """
        Valida si el usuario tiene permisos para crear productos
        Método puedeCrearProducto(): bool de la documentación
        """
        try:
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s AND activo = TRUE",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                return False
            
            # Solo instructores e inspectores pueden crear productos
            return user['rol'] in ['instructor', 'inspector']
            
        except Exception:
            return False
    
    def puede_gestionar_materiales(self, user_id: int) -> bool:
        """
        Valida permisos para gestionar materiales
        Método puedeGestionarMateriales(): bool de la documentación
        """
        try:
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s AND activo = TRUE",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                return False
            
            # Solo instructores e inspectores pueden gestionar materiales
            return user['rol'] in ['instructor', 'inspector']
            
        except Exception:
            return False
    
    def leer_qr(self, user_id: int, qr_data: str) -> Optional[Dict[str, Any]]:
        """
        Permite leer un código QR y obtener un producto
        Método leerQR(qr: str): Producto de la documentación
        """
        try:
            # Verificar que el usuario tenga permisos
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s AND activo = TRUE",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                return None
            
            # Intentar decodificar el QR como ID de producto
            try:
                # Si el QR contiene directamente un ID de producto
                producto_id = int(qr_data)
                producto = execute_query(
                    """SELECT p.*, 
                              COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
                       FROM productos p
                       LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                       WHERE p.id = %s AND p.activo = TRUE
                       GROUP BY p.id""",
                    (producto_id,),
                    fetch_one=True
                )
                
                if producto:
                    return producto
                    
            except ValueError:
                pass
            
            # Intentar decodificar como código de producto
            producto = execute_query(
                """SELECT p.*, 
                          COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
                   FROM productos p
                   LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                   WHERE p.codigo = %s AND p.activo = TRUE
                   GROUP BY p.id""",
                (qr_data,),
                fetch_one=True
            )
            
            if producto:
                return producto
            
            # Intentar decodificar como URL que contiene información del producto
            if qr_data.startswith('http'):
                # Extraer ID del producto de la URL
                import re
                match = re.search(r'/productos?/(\d+)', qr_data)
                if match:
                    producto_id = int(match.group(1))
                    producto = execute_query(
                        """SELECT p.*, 
                                  COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual
                           FROM productos p
                           LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                           WHERE p.id = %s AND p.activo = TRUE
                           GROUP BY p.id""",
                        (producto_id,),
                        fetch_one=True
                    )
                    
                    if producto:
                        return producto
            
            return None
            
        except Exception:
            return None
    
    def get_user_permissions(self, user_id: int) -> Dict[str, bool]:
        """Obtener todos los permisos del usuario"""
        try:
            user = execute_query(
                "SELECT rol FROM usuarios WHERE id = %s AND activo = TRUE",
                (user_id,),
                fetch_one=True
            )
            
            if not user:
                return {}
            
            rol = user['rol']
            
            permisos = {
                'puede_crear_producto': rol in ['instructor', 'inspector'],
                'puede_gestionar_materiales': rol in ['instructor', 'inspector'],
                'puede_crear_ordenes': True,  # Todos pueden crear órdenes
                'puede_ver_todas_ordenes': rol in ['instructor', 'inspector'],
                'puede_eliminar_ordenes': rol == 'instructor',
                'puede_gestionar_proveedores': rol in ['instructor', 'inspector'],
                'puede_configurar_productos': rol in ['instructor', 'inspector'],
                'puede_ver_reportes': True,  # Todos pueden ver reportes básicos
                'puede_administrar_usuarios': rol == 'instructor',
                'puede_usar_qr': True,  # Todos pueden usar QR
                'es_instructor': rol == 'instructor',
                'es_inspector': rol == 'inspector',
                'es_aprendiz': rol == 'aprendiz'
            }
            
            return permisos
            
        except Exception:
            return {}
    
    def get_user_stats(self, user_id: int) -> Dict[str, Any]:
        """Obtener estadísticas del usuario"""
        try:
            # Estadísticas de órdenes del usuario
            stats_ordenes = execute_query(
                """SELECT 
                    COUNT(*) as total_ordenes,
                    COUNT(CASE WHEN estado_orden = 'pendiente' THEN 1 END) as ordenes_pendientes,
                    COUNT(CASE WHEN estado_orden = 'completada' THEN 1 END) as ordenes_completadas,
                    COALESCE(SUM(total), 0) as valor_total_ordenes
                   FROM ordenes 
                   WHERE id_usuario = %s""",
                (user_id,),
                fetch_one=True
            )
            
            # Estadísticas de movimientos del usuario
            stats_movimientos = execute_query(
                """SELECT 
                    COUNT(*) as total_movimientos,
                    COUNT(CASE WHEN tipo = 'entrada' THEN 1 END) as movimientos_entrada,
                    COUNT(CASE WHEN tipo = 'salida' THEN 1 END) as movimientos_salida,
                    COALESCE(SUM(CASE WHEN tipo = 'entrada' THEN cantidad ELSE 0 END), 0) as cantidad_entradas,
                    COALESCE(SUM(CASE WHEN tipo = 'salida' THEN cantidad ELSE 0 END), 0) as cantidad_salidas
                   FROM movimientos 
                   WHERE usuario_id = %s""",
                (user_id,),
                fetch_one=True
            )
            
            # Productos asignados
            productos_asignados = len(self.get_productos_asignados(user_id))
            
            return {
                'ordenes': {
                    'total': stats_ordenes['total_ordenes'],
                    'pendientes': stats_ordenes['ordenes_pendientes'],
                    'completadas': stats_ordenes['ordenes_completadas'],
                    'valor_total': float(stats_ordenes['valor_total_ordenes'])
                },
                'movimientos': {
                    'total': stats_movimientos['total_movimientos'],
                    'entradas': stats_movimientos['movimientos_entrada'],
                    'salidas': stats_movimientos['movimientos_salida'],
                    'cantidad_entradas': stats_movimientos['cantidad_entradas'],
                    'cantidad_salidas': stats_movimientos['cantidad_salidas']
                },
                'productos_asignados': productos_asignados
            }
            
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error al obtener estadísticas: {str(e)}")

# Instancia global del servicio de usuario
usuario_service = UsuarioService()
