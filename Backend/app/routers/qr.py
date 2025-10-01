from fastapi import APIRouter, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import qrcode
from io import BytesIO
import base64
import socket
import os
from datetime import datetime
import shutil
import cv2
import json
from pathlib import Path

# Importar YOLO con manejo de errores
try:
    from ultralytics import YOLO
    YOLO_AVAILABLE = True
except ImportError:
    YOLO_AVAILABLE = False
    print("Warning: YOLO not available. Install ultralytics to use object detection features.")

router = APIRouter()

# Directorios
BACKEND_DIR = Path(__file__).parent.parent.parent
UPLOAD_DIR = BACKEND_DIR / "uploads"
RESULTS_DIR = BACKEND_DIR / "results"
STATIC_DIR = BACKEND_DIR / "static"

# Asegurar que existen los directorios
UPLOAD_DIR.mkdir(exist_ok=True)
RESULTS_DIR.mkdir(exist_ok=True)
STATIC_DIR.mkdir(exist_ok=True)

# Cargar modelo YOLO si está disponible
model = None
if YOLO_AVAILABLE:
    model_path = BACKEND_DIR / "best.pt"
    if model_path.exists():
        try:
            model = YOLO(str(model_path))
            print(f"✅ Modelo YOLO cargado desde {model_path}")
        except Exception as e:
            print(f"❌ Error al cargar modelo YOLO: {e}")
            model = None
    else:
        print(f"❌ Archivo del modelo no encontrado: {model_path}")

def get_local_ip():
    """Obtiene la IP local automáticamente."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

@router.get("/", response_class=HTMLResponse)
async def generate_qr():
    """Genera un código QR para conectar dispositivos móviles"""
    local_ip = get_local_ip()
    url = f"http://{local_ip}:8000/api/qr/connect"

    # Generar QR
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    img_byte_arr = BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_byte_arr = img_byte_arr.getvalue()
    qr_base64 = base64.b64encode(img_byte_arr).decode("utf-8")

    html_content = f"""
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sistema de Inventario - QR</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                margin: 0;
                padding: 20px;
                box-sizing: border-box;
            }}
            .container {{
                background: white;
                padding: 40px;
                border-radius: 20px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                text-align: center;
                max-width: 500px;
                width: 100%;
            }}
            h1 {{
                color: #333;
                margin-bottom: 20px;
                font-size: 2.5em;
            }}
            .subtitle {{
                color: #666;
                margin-bottom: 30px;
                font-size: 1.2em;
            }}
            .qr-container {{
                margin: 30px 0;
                padding: 20px;
                background: #f9f9f9;
                border-radius: 15px;
                border: 3px dashed #ddd;
            }}
            .qr-code {{
                max-width: 300px;
                width: 100%;
                height: auto;
                border-radius: 10px;
            }}
            .url-info {{
                margin-top: 20px;
                padding: 15px;
                background: #e8f4fd;
                border-radius: 10px;
                border-left: 4px solid #007bff;
            }}
            .url-text {{
                color: #007bff;
                font-weight: bold;
                word-break: break-all;
            }}
            .instructions {{
                margin-top: 20px;
                color: #666;
                font-style: italic;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🏭 Sistema de Inventario</h1>
            <p class="subtitle">Escanea el código QR para usar la app móvil</p>
            
            <div class="qr-container">
                <img src="data:image/png;base64,{qr_base64}" alt="QR Code" class="qr-code">
            </div>
            
            <div class="url-info">
                <p><strong>URL de conexión:</strong></p>
                <p class="url-text">{url}</p>
            </div>
            
            <div class="instructions">
                <p>📱 Abre la cámara de tu teléfono</p>
                <p>🔍 Apunta hacia el código QR</p>
                <p>📲 Toca la notificación para abrir</p>
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.get("/connect", response_class=HTMLResponse)
async def mobile_connect():
    """Página optimizada para dispositivos móviles"""
    html_content = """
    <!DOCTYPE html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Sistema de Inventario - Móvil</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
            }
            
            .container {
                max-width: 400px;
                margin: 0 auto;
                background: white;
                border-radius: 20px;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            }
            
            .header {
                background: linear-gradient(45deg, #22333B, #34444b);
                color: white;
                padding: 30px 20px;
                text-align: center;
            }
            
            .header h1 {
                font-size: 1.8em;
                margin-bottom: 10px;
            }
            
            .content {
                padding: 30px 20px;
            }
            
            .section {
                margin-bottom: 30px;
                padding: 20px;
                border-radius: 15px;
                border: 1px solid #e0e0e0;
            }
            
            .section h2 {
                color: #22333B;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .form-group {
                margin-bottom: 15px;
            }
            
            input, button {
                width: 100%;
                padding: 15px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            input:focus {
                border-color: #667eea;
                outline: none;
                box-shadow: 0 0 10px rgba(102, 126, 234, 0.2);
            }
            
            button {
                background: linear-gradient(45deg, #667eea, #764ba2);
                color: white;
                border: none;
                cursor: pointer;
                font-weight: bold;
                text-transform: uppercase;
                letter-spacing: 1px;
            }
            
            button:hover {
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            
            button:active {
                transform: translateY(0);
            }
            
            .file-input-wrapper {
                position: relative;
                overflow: hidden;
                border: 2px dashed #667eea;
                border-radius: 10px;
                padding: 20px;
                text-align: center;
                background: #f8f9ff;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .file-input-wrapper:hover {
                background: #f0f2ff;
                border-color: #5a6fd8;
            }
            
            .file-input-wrapper input[type=file] {
                position: absolute;
                left: -9999px;
            }
            
            .upload-icon {
                font-size: 2em;
                color: #667eea;
                margin-bottom: 10px;
            }
            
            .response {
                margin-top: 20px;
                padding: 15px;
                border-radius: 10px;
                display: none;
            }
            
            .response.success {
                background: #d4edda;
                color: #155724;
                border: 1px solid #c3e6cb;
            }
            
            .response.error {
                background: #f8d7da;
                color: #721c24;
                border: 1px solid #f5c6cb;
            }
            
            .loading {
                display: none;
                text-align: center;
                color: #667eea;
                margin: 20px 0;
            }
            
            .loading::after {
                content: '';
                display: inline-block;
                width: 20px;
                height: 20px;
                border: 3px solid #f3f3f3;
                border-top: 3px solid #667eea;
                border-radius: 50%;
                animation: spin 1s linear infinite;
                margin-left: 10px;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🏭 Sistema de Inventario</h1>
                <p>Aplicación Móvil</p>
            </div>
            
            <div class="content">
                <div class="section">
                    <h2>📝 Enviar Datos</h2>
                    <form id="dataForm">
                        <div class="form-group">
                            <input type="text" id="dataInput" placeholder="Ingresa código de producto, comentarios...">
                        </div>
                        <button type="submit">Enviar Datos</button>
                    </form>
                    <div id="dataResponse" class="response"></div>
                </div>
                
                <div class="section">
                    <h2>📸 Detectar Objetos</h2>
                    <form id="photoForm" enctype="multipart/form-data">
                        <div class="file-input-wrapper" onclick="document.getElementById('photoInput').click()">
                            <div class="upload-icon">📷</div>
                            <p>Toca para tomar foto o seleccionar imagen</p>
                            <input type="file" id="photoInput" accept="image/*" capture="environment">
                        </div>
                        <div style="margin-top: 15px;">
                            <button type="submit">Procesar con IA</button>
                        </div>
                    </form>
                    <div id="photoResponse" class="response"></div>
                    <div id="loading" class="loading">Procesando imagen...</div>
                </div>
            </div>
        </div>

        <script>
            // Manejar envío de datos
            document.getElementById('dataForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const data = document.getElementById('dataInput').value;
                const response = document.getElementById('dataResponse');
                
                if (!data.trim()) {
                    response.className = 'response error';
                    response.textContent = 'Por favor ingresa algún dato';
                    response.style.display = 'block';
                    return;
                }
                
                try {
                    const formData = new FormData();
                    formData.append('data', data);
                    
                    const result = await fetch('/api/qr/send_data', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const jsonResult = await result.json();
                    
                    response.className = 'response success';
                    response.textContent = '✅ ' + jsonResult.message;
                    response.style.display = 'block';
                    
                    document.getElementById('dataInput').value = '';
                } catch (error) {
                    response.className = 'response error';
                    response.textContent = '❌ Error: ' + error.message;
                    response.style.display = 'block';
                }
            });
            
            // Actualizar texto cuando se selecciona archivo
            document.getElementById('photoInput').addEventListener('change', function(e) {
                const wrapper = this.parentElement;
                const fileName = e.target.files[0]?.name;
                if (fileName) {
                    wrapper.innerHTML = `
                        <div class="upload-icon">✅</div>
                        <p>Archivo seleccionado: ${fileName}</p>
                        <input type="file" id="photoInput" accept="image/*" capture="environment">
                    `;
                    // Restaurar event listener
                    document.getElementById('photoInput').addEventListener('change', arguments.callee);
                }
            });
            
            // Manejar envío de fotos
            document.getElementById('photoForm').addEventListener('submit', async function(e) {
                e.preventDefault();
                const fileInput = document.getElementById('photoInput');
                const response = document.getElementById('photoResponse');
                const loading = document.getElementById('loading');
                
                if (!fileInput.files[0]) {
                    response.className = 'response error';
                    response.textContent = 'Por favor selecciona una imagen';
                    response.style.display = 'block';
                    return;
                }
                
                loading.style.display = 'block';
                response.style.display = 'none';
                
                try {
                    const formData = new FormData();
                    formData.append('file', fileInput.files[0]);
                    
                    const result = await fetch('/api/qr/upload_photo', {
                        method: 'POST',
                        body: formData
                    });
                    
                    const jsonResult = await result.json();
                    
                    response.className = 'response success';
                    response.innerHTML = `
                        <p>✅ ${jsonResult.message}</p>
                        <p><strong>Archivo:</strong> ${jsonResult.filename}</p>
                        <p><strong>Resultado:</strong> ${jsonResult.result}</p>
                        ${jsonResult.detections ? `<p><strong>Detecciones:</strong> ${jsonResult.detections}</p>` : ''}
                    `;
                    response.style.display = 'block';
                    
                    // Reset form
                    fileInput.value = '';
                    document.querySelector('.file-input-wrapper').innerHTML = `
                        <div class="upload-icon">📷</div>
                        <p>Toca para tomar foto o seleccionar imagen</p>
                        <input type="file" id="photoInput" accept="image/*" capture="environment">
                    `;
                    
                } catch (error) {
                    response.className = 'response error';
                    response.textContent = '❌ Error: ' + error.message;
                    response.style.display = 'block';
                } finally {
                    loading.style.display = 'none';
                }
            });
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html_content)

@router.post("/send_data")
async def receive_data(data: str = Form(...)):
    """Recibe datos de texto desde dispositivos móviles"""
    print(f"📲 Datos recibidos desde el celular: {data}")
    
    # Guardar los datos en un archivo log
    timestamp = datetime.now().isoformat()
    log_entry = {
        "timestamp": timestamp,
        "type": "text_data",
        "data": data
    }
    
    log_file = BACKEND_DIR / "qr_data_log.json"
    logs = []
    
    # Leer logs existentes
    if log_file.exists():
        try:
            with open(log_file, 'r', encoding='utf-8') as f:
                logs = json.load(f)
        except:
            logs = []
    
    # Agregar nuevo log
    logs.append(log_entry)
    
    # Mantener solo los últimos 1000 registros
    if len(logs) > 1000:
        logs = logs[-1000:]
    
    # Guardar logs
    with open(log_file, 'w', encoding='utf-8') as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)
    
    return {"message": f"Datos recibidos y guardados: {data}", "timestamp": timestamp}

@router.post("/upload_photo")
async def upload_photo(file: UploadFile = File(...)):
    """Recibe y procesa fotos desde dispositivos móviles usando YOLO"""
    if not model and YOLO_AVAILABLE:
        raise HTTPException(status_code=500, detail="Modelo YOLO no disponible")
    elif not YOLO_AVAILABLE:
        raise HTTPException(status_code=500, detail="YOLO no está instalado. Instala 'ultralytics' para usar esta función.")
    
    # Validar tipo de archivo
    if not file.content_type.startswith('image/'):
        raise HTTPException(status_code=400, detail="El archivo debe ser una imagen")
    
    try:
        # Generar nombre único
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{timestamp}_{file.filename}"
        file_path = UPLOAD_DIR / filename
        
        # Guardar archivo
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        
        print(f"📸 Foto recibida y guardada en {file_path}")
        
        # Procesar con YOLO
        results = model(str(file_path))
        
        # Obtener información de detecciones
        detections_info = []
        if results and len(results) > 0:
            boxes = results[0].boxes
            if boxes is not None:
                for box in boxes:
                    confidence = float(box.conf[0])
                    class_id = int(box.cls[0])
                    class_name = model.names[class_id] if hasattr(model, 'names') else f"Class_{class_id}"
                    detections_info.append({
                        "class": class_name,
                        "confidence": round(confidence * 100, 2)
                    })
        
        # Crear imagen anotada
        annotated_frame = results[0].plot() if results else None
        
        # Guardar resultado
        result_filename = f"result_{filename}"
        result_path = RESULTS_DIR / result_filename
        
        if annotated_frame is not None:
            cv2.imwrite(str(result_path), annotated_frame)
            print(f"✅ Resultado procesado y guardado en {result_path}")
        
        # Guardar log de procesamiento
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "type": "photo_processing",
            "original_file": filename,
            "result_file": result_filename,
            "detections": detections_info
        }
        
        log_file = BACKEND_DIR / "qr_data_log.json"
        logs = []
        
        if log_file.exists():
            try:
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = json.load(f)
            except:
                logs = []
        
        logs.append(log_entry)
        
        if len(logs) > 1000:
            logs = logs[-1000:]
        
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(logs, f, ensure_ascii=False, indent=2)
        
        return {
            "message": "Foto subida y procesada con éxito",
            "filename": filename,
            "result": result_filename,
            "detections": f"Encontrados {len(detections_info)} objetos" if detections_info else "No se detectaron objetos",
            "detection_details": detections_info
        }
        
    except Exception as e:
        print(f"❌ Error procesando foto: {e}")
        raise HTTPException(status_code=500, detail=f"Error procesando imagen: {str(e)}")

@router.get("/logs")
async def get_qr_logs():
    """Obtiene los logs de datos QR recibidos"""
    log_file = BACKEND_DIR / "qr_data_log.json"
    
    if not log_file.exists():
        return {"logs": [], "message": "No hay logs disponibles"}
    
    try:
        with open(log_file, 'r', encoding='utf-8') as f:
            logs = json.load(f)
        
        return {
            "logs": logs[-50:],  # Últimos 50 registros
            "total_logs": len(logs),
            "message": "Logs obtenidos exitosamente"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error leyendo logs: {str(e)}")

@router.get("/status")
async def qr_system_status():
    """Obtiene el estado del sistema QR"""
    return {
        "yolo_available": YOLO_AVAILABLE,
        "model_loaded": model is not None,
        "upload_dir_exists": UPLOAD_DIR.exists(),
        "results_dir_exists": RESULTS_DIR.exists(),
        "local_ip": get_local_ip(),
        "timestamp": datetime.now().isoformat()
    }