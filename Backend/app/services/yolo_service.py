"""
Servicio YOLO dedicado según la documentación del proyecto
Implementa la clase YoloService (Clase --3)
"""

import cv2
import numpy as np
import json
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import shutil
import os

# Importar YOLO con manejo de errores
try:
    from ultralytics import YOLO
    YOLO_AVAILABLE = True
except ImportError:
    YOLO_AVAILABLE = False
    print("Warning: YOLO not available. Install ultralytics to use object detection features.")

class YoloService:
    """
    Clase YoloService según documentación (Clase --3)
    Atributos: -modelo: YOLO(best.py)
    Métodos: procesarImagen(file_path: str): str
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.modelo = None
        self.model_loaded = False
        self.model_info = {}
        self.detection_history = []
        
        # Configurar rutas
        self.backend_dir = Path(__file__).parent.parent.parent
        self.upload_dir = self.backend_dir / "uploads"
        self.results_dir = self.backend_dir / "results"
        self.static_dir = self.backend_dir / "static"
        
        # Asegurar que existen los directorios
        self.upload_dir.mkdir(exist_ok=True)
        self.results_dir.mkdir(exist_ok=True)
        self.static_dir.mkdir(exist_ok=True)
        
        # Cargar modelo si está disponible
        if YOLO_AVAILABLE:
            self._cargar_modelo(model_path)
    
    def _cargar_modelo(self, model_path: Optional[str] = None):
        """Cargar modelo YOLO"""
        try:
            if not model_path:
                model_path = self.backend_dir / "best.pt"
            
            if not Path(model_path).exists():
                print(f"❌ Archivo del modelo no encontrado: {model_path}")
                return
            
            self.modelo = YOLO(str(model_path))
            self.model_loaded = True
            
            # Obtener información del modelo
            self.model_info = {
                "model_path": str(model_path),
                "model_size": Path(model_path).stat().st_size,
                "loaded_at": datetime.now().isoformat(),
                "classes": getattr(self.modelo, 'names', {}),
                "model_type": "YOLO"
            }
            
            print(f"✅ Modelo YOLO cargado desde {model_path}")
            
        except Exception as e:
            print(f"❌ Error al cargar modelo YOLO: {e}")
            self.modelo = None
            self.model_loaded = False
    
    def procesarImagen(self, file_path: str) -> str:
        """
        Recibe la ruta de una imagen y devuelve un string con los resultados
        Implementa el método procesarImagen(file_path: str): str de la documentación
        """
        try:
            if not self.is_available():
                return "Error: Servicio YOLO no disponible"
            
            if not self.model_loaded:
                return "Error: Modelo YOLO no cargado"
            
            # Verificar que el archivo existe
            if not Path(file_path).exists():
                return f"Error: Archivo no encontrado: {file_path}"
            
            # Procesar imagen con YOLO
            results = self.modelo(file_path)
            
            # Procesar resultados
            detections_info = self._extraer_detecciones(results)
            
            # Crear imagen anotada
            result_path = self._crear_imagen_anotada(results, file_path)
            
            # Guardar en historial
            detection_record = {
                "timestamp": datetime.now().isoformat(),
                "file_path": file_path,
                "result_path": result_path,
                "detections": detections_info,
                "total_detections": len(detections_info)
            }
            
            self.detection_history.append(detection_record)
            
            # Mantener solo los últimos 100 registros
            if len(self.detection_history) > 100:
                self.detection_history = self.detection_history[-100:]
            
            # Crear string de resultado
            result_string = self._crear_string_resultado(detections_info, result_path)
            
            return result_string
            
        except Exception as e:
            error_msg = f"Error al procesar imagen: {str(e)}"
            print(f"❌ {error_msg}")
            return error_msg
    
    def _extraer_detecciones(self, results) -> List[Dict[str, Any]]:
        """Extraer información de las detecciones"""
        detections_info = []
        
        try:
            if results and len(results) > 0:
                boxes = results[0].boxes
                if boxes is not None:
                    for i, box in enumerate(boxes):
                        confidence = float(box.conf[0])
                        class_id = int(box.cls[0])
                        class_name = self.modelo.names[class_id] if hasattr(self.modelo, 'names') else f"Class_{class_id}"
                        
                        # Obtener coordenadas del bounding box
                        coords = box.xyxy[0].tolist()
                        
                        detection = {
                            "id": i,
                            "class_id": class_id,
                            "class_name": class_name,
                            "confidence": round(confidence * 100, 2),
                            "confidence_raw": confidence,
                            "bbox": {
                                "x1": coords[0],
                                "y1": coords[1],
                                "x2": coords[2],
                                "y2": coords[3]
                            },
                            "area": (coords[2] - coords[0]) * (coords[3] - coords[1])
                        }
                        
                        detections_info.append(detection)
                        
        except Exception as e:
            print(f"❌ Error al extraer detecciones: {e}")
        
        return detections_info
    
    def _crear_imagen_anotada(self, results, original_path: str) -> str:
        """Crear imagen anotada con las detecciones"""
        try:
            annotated_frame = results[0].plot() if results else None
            
            if annotated_frame is not None:
                # Generar nombre del archivo resultado
                original_name = Path(original_path).stem
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                result_filename = f"yolo_result_{original_name}_{timestamp}.jpg"
                result_path = self.results_dir / result_filename
                
                # Guardar imagen anotada
                cv2.imwrite(str(result_path), annotated_frame)
                print(f"✅ Resultado YOLO guardado en {result_path}")
                
                return str(result_path)
            
            return ""
            
        except Exception as e:
            print(f"❌ Error al crear imagen anotada: {e}")
            return ""
    
    def _crear_string_resultado(self, detections_info: List[Dict[str, Any]], result_path: str) -> str:
        """Crear string de resultado según el método de la documentación"""
        try:
            if not detections_info:
                return "No se detectaron objetos en la imagen"
            
            # Crear resumen
            total_detections = len(detections_info)
            classes_detected = list(set([det['class_name'] for det in detections_info]))
            avg_confidence = sum([det['confidence'] for det in detections_info]) / total_detections
            
            # Crear string resultado
            result_parts = [
                f"YOLO Detection Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Total objetos detectados: {total_detections}",
                f"Clases encontradas: {', '.join(classes_detected)}",
                f"Confianza promedio: {avg_confidence:.2f}%",
                f"Imagen resultado: {Path(result_path).name if result_path else 'N/A'}",
                "",
                "Detecciones detalladas:"
            ]
            
            # Agregar cada detección
            for i, detection in enumerate(detections_info, 1):
                det_string = (
                    f"{i}. {detection['class_name']} "
                    f"(confianza: {detection['confidence']:.2f}%) "
                    f"[{detection['bbox']['x1']:.0f},{detection['bbox']['y1']:.0f},"
                    f"{detection['bbox']['x2']:.0f},{detection['bbox']['y2']:.0f}]"
                )
                result_parts.append(det_string)
            
            return "\n".join(result_parts)
            
        except Exception as e:
            return f"Error al crear string resultado: {str(e)}"
    
    def is_available(self) -> bool:
        """Verificar si el servicio YOLO está disponible"""
        return YOLO_AVAILABLE and self.model_loaded
    
    def get_status(self) -> Dict[str, Any]:
        """Obtener estado del servicio YOLO"""
        return {
            "yolo_available": YOLO_AVAILABLE,
            "model_loaded": self.model_loaded,
            "model_info": self.model_info,
            "upload_dir_exists": self.upload_dir.exists(),
            "results_dir_exists": self.results_dir.exists(),
            "total_detections_history": len(self.detection_history),
            "timestamp": datetime.now().isoformat()
        }

# Instancia global del servicio YOLO
yolo_service = YoloService()
