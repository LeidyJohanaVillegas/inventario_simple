"""
Servicio QR dedicado según la documentación del proyecto
Implementa la clase QRService (Clase --4)
"""

import qrcode
import cv2
import numpy as np
from io import BytesIO
import base64
import socket
import json
from datetime import datetime
from typing import Optional, Dict, Any, Union
from pathlib import Path
from pyzbar import pyzbar
from PIL import Image
import requests

from ..database import execute_query

class QRService:
    """
    Clase QRService según documentación (Clase --4)
    Métodos: generarQR(url: str): str, decodificarQR(qr: str): Producto
    """
    
    def __init__(self):
        self.qr_config = {
            "version": 1,
            "error_correction": qrcode.constants.ERROR_CORRECT_L,
            "box_size": 10,
            "border": 4
        }
    
    def get_local_ip(self) -> str:
        """Obtener la IP local automáticamente"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def generar_qr(self, url: str) -> str:
        """
        Genera un código QR a partir de una URL y devuelve la imagen QR en base64
        Implementa el método generarQR(url: str): str de la documentación
        """
        try:
            # Crear objeto QR
            qr = qrcode.QRCode(
                version=self.qr_config["version"],
                error_correction=self.qr_config["error_correction"],
                box_size=self.qr_config["box_size"],
                border=self.qr_config["border"]
            )
            
            # Agregar datos
            qr.add_data(url)
            qr.make(fit=True)
            
            # Crear imagen
            img = qr.make_image(fill_color="black", back_color="white")
            
            # Convertir a base64
            img_byte_arr = BytesIO()
            img.save(img_byte_arr, format='PNG')
            img_byte_arr = img_byte_arr.getvalue()
            qr_base64 = base64.b64encode(img_byte_arr).decode("utf-8")
            
            return qr_base64
            
        except Exception as e:
            raise Exception(f"Error al generar QR: {str(e)}")
    
    def generar_qr_producto(self, producto_id: int) -> str:
        """Generar QR específico para un producto"""
        try:
            # Verificar que el producto existe
            producto = execute_query(
                "SELECT id, codigo, nombre FROM productos WHERE id = %s AND activo = TRUE",
                (producto_id,),
                fetch_one=True
            )
            
            if not producto:
                raise Exception("Producto no encontrado")
            
            # Crear URL del producto
            local_ip = self.get_local_ip()
            producto_url = f"http://{local_ip}:8000/api/productos/{producto_id}"
            
            # Generar QR
            qr_base64 = self.generar_qr(producto_url)
            
            return qr_base64
            
        except Exception as e:
            raise Exception(f"Error al generar QR del producto: {str(e)}")
    
    def generar_qr_con_datos(self, datos: Dict[str, Any]) -> str:
        """Generar QR con datos estructurados en JSON"""
        try:
            datos_json = json.dumps(datos, ensure_ascii=False)
            return self.generar_qr(datos_json)
        except Exception as e:
            raise Exception(f"Error al generar QR con datos: {str(e)}")
    
    def decodificar_qr(self, qr_data: Union[str, bytes, np.ndarray]) -> Optional[Dict[str, Any]]:
        """
        Lee/decodifica un código QR y devuelve un objeto de tipo Producto
        Implementa el método decodificarQR(qr: str): Producto de la documentación
        """
        try:
            producto_info = None
            
            # Caso 1: qr_data es una string (datos directos)
            if isinstance(qr_data, str):
                producto_info = self._procesar_qr_string(qr_data)
            
            # Caso 2: qr_data es una imagen (bytes o numpy array)
            elif isinstance(qr_data, (bytes, np.ndarray)):
                decoded_strings = self._decodificar_qr_imagen(qr_data)
                for decoded_string in decoded_strings:
                    producto_info = self._procesar_qr_string(decoded_string)
                    if producto_info:
                        break
            
            return producto_info
            
        except Exception as e:
            raise Exception(f"Error al decodificar QR: {str(e)}")
    
    def _decodificar_qr_imagen(self, imagen_data: Union[bytes, np.ndarray]) -> list:
        """Decodificar QR desde imagen usando pyzbar"""
        try:
            # Convertir a imagen PIL si es necesario
            if isinstance(imagen_data, bytes):
                imagen = Image.open(BytesIO(imagen_data))
            elif isinstance(imagen_data, np.ndarray):
                imagen = Image.fromarray(imagen_data)
            else:
                raise Exception("Formato de imagen no soportado")
            
            # Decodificar QR codes
            qr_codes = pyzbar.decode(imagen)
            
            decoded_strings = []
            for qr_code in qr_codes:
                decoded_string = qr_code.data.decode('utf-8')
                decoded_strings.append(decoded_string)
            
            return decoded_strings
            
        except Exception as e:
            raise Exception(f"Error al decodificar imagen QR: {str(e)}")
    
    def _procesar_qr_string(self, qr_string: str) -> Optional[Dict[str, Any]]:
        """Procesar string de QR y obtener información del producto"""
        try:
            # Caso 1: ID numérico directo
            try:
                producto_id = int(qr_string)
                return self._obtener_producto_por_id(producto_id)
            except ValueError:
                pass
            
            # Caso 2: Código de producto
            producto = self._obtener_producto_por_codigo(qr_string)
            if producto:
                return producto
            
            # Caso 3: URL que contiene información del producto
            if qr_string.startswith('http'):
                return self._procesar_qr_url(qr_string)
            
            # Caso 4: JSON con datos estructurados
            try:
                datos_json = json.loads(qr_string)
                if 'producto_id' in datos_json:
                    return self._obtener_producto_por_id(datos_json['producto_id'])
                elif 'codigo' in datos_json:
                    return self._obtener_producto_por_codigo(datos_json['codigo'])
            except json.JSONDecodeError:
                pass
            
            return None
            
        except Exception as e:
            raise Exception(f"Error al procesar QR string: {str(e)}")
    
    def _procesar_qr_url(self, url: str) -> Optional[Dict[str, Any]]:
        """Procesar URL de QR para extraer información del producto"""
        try:
            import re
            
            # Buscar patrón de ID de producto en la URL
            patterns = [
                r'/productos?/(\d+)',
                r'producto_id=(\d+)',
                r'id=(\d+)',
                r'/api/productos/(\d+)'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, url)
                if match:
                    producto_id = int(match.group(1))
                    return self._obtener_producto_por_id(producto_id)
            
            # Intentar hacer request a la URL si es un endpoint válido
            if '/api/productos/' in url:
                try:
                    response = requests.get(url, timeout=5)
                    if response.status_code == 200:
                        return response.json()
                except:
                    pass
            
            return None
            
        except Exception:
            return None
    
    def _obtener_producto_por_id(self, producto_id: int) -> Optional[Dict[str, Any]]:
        """Obtener producto por ID"""
        try:
            producto = execute_query(
                """SELECT p.*, 
                          COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual,
                          pr.nombre as proveedor_nombre
                   FROM productos p
                   LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                   LEFT JOIN proveedores pr ON p.id_proveedor = pr.id_proveedor
                   WHERE p.id = %s AND p.activo = TRUE
                   GROUP BY p.id""",
                (producto_id,),
                fetch_one=True
            )
            
            if producto:
                # Agregar información adicional
                producto['qr_decoded_from'] = 'id'
                producto['qr_decoded_at'] = datetime.now().isoformat()
                
            return producto
            
        except Exception:
            return None
    
    def _obtener_producto_por_codigo(self, codigo: str) -> Optional[Dict[str, Any]]:
        """Obtener producto por código"""
        try:
            producto = execute_query(
                """SELECT p.*, 
                          COALESCE(SUM(l.cantidad_disponible), 0) as stock_actual,
                          pr.nombre as proveedor_nombre
                   FROM productos p
                   LEFT JOIN lotes l ON p.id = l.producto_id AND l.activo = TRUE
                   LEFT JOIN proveedores pr ON p.id_proveedor = pr.id_proveedor
                   WHERE p.codigo = %s AND p.activo = TRUE
                   GROUP BY p.id""",
                (codigo,),
                fetch_one=True
            )
            
            if producto:
                # Agregar información adicional
                producto['qr_decoded_from'] = 'codigo'
                producto['qr_decoded_at'] = datetime.now().isoformat()
                
            return producto
            
        except Exception:
            return None
    
    def generar_qr_lote(self, lote_id: int) -> str:
        """Generar QR para un lote específico"""
        try:
            # Verificar que el lote existe
            lote = execute_query(
                """SELECT l.*, p.nombre as producto_nombre, p.codigo as producto_codigo
                   FROM lotes l
                   JOIN productos p ON l.producto_id = p.id
                   WHERE l.id = %s AND l.activo = TRUE""",
                (lote_id,),
                fetch_one=True
            )
            
            if not lote:
                raise Exception("Lote no encontrado")
            
            # Crear datos del lote para QR
            datos_lote = {
                "tipo": "lote",
                "lote_id": lote_id,
                "numero_lote": lote['numero_lote'],
                "producto_id": lote['producto_id'],
                "producto_codigo": lote['producto_codigo'],
                "cantidad_disponible": lote['cantidad_disponible'],
                "fecha_vencimiento": lote['fecha_vencimiento'].isoformat() if lote['fecha_vencimiento'] else None
            }
            
            return self.generar_qr_con_datos(datos_lote)
            
        except Exception as e:
            raise Exception(f"Error al generar QR del lote: {str(e)}")
    
    def decodificar_qr_desde_archivo(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Decodificar QR desde archivo de imagen"""
        try:
            # Leer imagen
            imagen = cv2.imread(file_path)
            if imagen is None:
                raise Exception("No se pudo leer la imagen")
            
            # Convertir a RGB para PIL
            imagen_rgb = cv2.cvtColor(imagen, cv2.COLOR_BGR2RGB)
            
            return self.decodificar_qr(imagen_rgb)
            
        except Exception as e:
            raise Exception(f"Error al decodificar QR desde archivo: {str(e)}")
    
    def validar_qr_producto(self, qr_data: str, producto_id_esperado: int) -> bool:
        """Validar que un QR corresponde a un producto específico"""
        try:
            producto_info = self.decodificar_qr(qr_data)
            
            if not producto_info:
                return False
            
            return producto_info.get('id') == producto_id_esperado
            
        except Exception:
            return False
    
    def generar_qr_movimiento(self, movimiento_id: int) -> str:
        """Generar QR para tracking de un movimiento"""
        try:
            # Verificar que el movimiento existe
            movimiento = execute_query(
                """SELECT m.*, l.numero_lote, p.nombre as producto_nombre
                   FROM movimientos m
                   JOIN lotes l ON m.lote_id = l.id
                   JOIN productos p ON l.producto_id = p.id
                   WHERE m.id = %s""",
                (movimiento_id,),
                fetch_one=True
            )
            
            if not movimiento:
                raise Exception("Movimiento no encontrado")
            
            # Crear URL de tracking
            local_ip = self.get_local_ip()
            tracking_url = f"http://{local_ip}:8000/api/movimientos/{movimiento_id}"
            
            return self.generar_qr(tracking_url)
            
        except Exception as e:
            raise Exception(f"Error al generar QR del movimiento: {str(e)}")
    
    def obtener_estadisticas_qr(self) -> Dict[str, Any]:
        """Obtener estadísticas de uso de QR"""
        try:
            # Estadísticas básicas (esto podría expandirse con una tabla de logs)
            stats = {
                "qr_service_active": True,
                "supported_formats": ["ID", "Código", "URL", "JSON"],
                "supported_types": ["producto", "lote", "movimiento"],
                "encoding_format": "UTF-8",
                "image_format": "PNG",
                "timestamp": datetime.now().isoformat()
            }
            
            return stats
            
        except Exception as e:
            raise Exception(f"Error al obtener estadísticas QR: {str(e)}")

# Instancia global del servicio QR
qr_service = QRService()
