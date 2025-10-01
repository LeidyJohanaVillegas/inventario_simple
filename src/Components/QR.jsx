import { useState } from 'react';
import '../App.css';

const QR = () => {
  const [textData, setTextData] = useState('');
  const [selectedFile, setSelectedFile] = useState(null);
  const [textResponse, setTextResponse] = useState('');
  const [photoResponse, setPhotoResponse] = useState('');
  const [isProcessing, setIsProcessing] = useState(false);
  const [logs, setLogs] = useState([]);
  const [showLogs, setShowLogs] = useState(false);

  const handleTextSubmit = async (e) => {
    e.preventDefault();
    if (!textData.trim()) {
      setTextResponse('Por favor ingresa algún dato');
      return;
    }

    try {
      const formData = new FormData();
      formData.append('data', textData);

      const response = await fetch('/api/qr/send_data', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      setTextResponse(`✅ ${result.message}`);
      setTextData('');
    } catch (error) {
      setTextResponse(`❌ Error: ${error.message}`);
    }
  };

  const handleFileChange = (e) => {
    setSelectedFile(e.target.files[0]);
    setPhotoResponse('');
  };

  const handlePhotoSubmit = async (e) => {
    e.preventDefault();
    if (!selectedFile) {
      setPhotoResponse('Por favor selecciona una imagen');
      return;
    }

    setIsProcessing(true);
    try {
      const formData = new FormData();
      formData.append('file', selectedFile);

      const response = await fetch('/api/qr/upload_photo', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();
      
      if (response.ok) {
        setPhotoResponse(`
          ✅ ${result.message}
          📁 Archivo: ${result.filename}
          🎯 ${result.detections}
          ${result.detection_details && result.detection_details.length > 0 ? 
            `🔍 Objetos detectados: ${result.detection_details.map(d => `${d.class} (${d.confidence}%)`).join(', ')}` 
            : ''
          }
        `);
      } else {
        setPhotoResponse(`❌ Error: ${result.detail || 'Error desconocido'}`);
      }
      
      setSelectedFile(null);
      document.getElementById('photoInput').value = '';
    } catch (error) {
      setPhotoResponse(`❌ Error: ${error.message}`);
    } finally {
      setIsProcessing(false);
    }
  };

  const openQRPage = () => {
    window.open('/api/qr/', '_blank');
  };

  const fetchLogs = async () => {
    try {
      const response = await fetch('/api/qr/logs');
      const result = await response.json();
      setLogs(result.logs || []);
      setShowLogs(true);
    } catch (error) {
      console.error('Error fetching logs:', error);
      setLogs([]);
    }
  };

  const checkStatus = async () => {
    try {
      const response = await fetch('/api/qr/status');
      const result = await response.json();
      
      let statusMessage = `
🔧 Estado del Sistema QR:
• YOLO disponible: ${result.yolo_available ? '✅' : '❌'}
• Modelo cargado: ${result.model_loaded ? '✅' : '❌'}
• Directorio uploads: ${result.upload_dir_exists ? '✅' : '❌'}
• Directorio results: ${result.results_dir_exists ? '✅' : '❌'}
• IP local: ${result.local_ip}
• Tiempo: ${new Date(result.timestamp).toLocaleString()}
      `;
      
      alert(statusMessage);
    } catch (error) {
      alert(`❌ Error verificando estado: ${error.message}`);
    }
  };

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="ordenes-section">
            <h2>📱 Sistema de Códigos QR</h2>
            
            <div className="btn-container-3">
              <button className="btn-components" onClick={openQRPage}>
                📱 Mostrar Código QR
              </button>
              <button className="btn-components" onClick={checkStatus}>
                🔧 Estado del Sistema
              </button>
              <button className="btn-components" onClick={fetchLogs}>
                📋 Ver Logs
              </button>
            </div>

            <div style={{ marginTop: '30px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '30px' }}>
              {/* Sección de envío de datos */}
              <div style={{ 
                padding: '20px', 
                border: '1px solid #ddd', 
                borderRadius: '10px',
                backgroundColor: '#f9f9f9'
              }}>
                <h3>📝 Enviar Datos de Texto</h3>
                <form onSubmit={handleTextSubmit}>
                  <input
                    type="text"
                    value={textData}
                    onChange={(e) => setTextData(e.target.value)}
                    placeholder="Código de producto, comentarios..."
                    style={{
                      width: '100%',
                      padding: '10px',
                      margin: '10px 0',
                      border: '1px solid #ccc',
                      borderRadius: '5px',
                      fontSize: '16px'
                    }}
                  />
                  <button 
                    type="submit" 
                    className="action-btn"
                    style={{ width: '100%', marginTop: '10px' }}
                  >
                    Enviar Datos
                  </button>
                </form>
                {textResponse && (
                  <div style={{
                    marginTop: '15px',
                    padding: '10px',
                    backgroundColor: textResponse.includes('❌') ? '#f8d7da' : '#d4edda',
                    color: textResponse.includes('❌') ? '#721c24' : '#155724',
                    borderRadius: '5px',
                    whiteSpace: 'pre-line'
                  }}>
                    {textResponse}
                  </div>
                )}
              </div>

              {/* Sección de detección de objetos */}
              <div style={{ 
                padding: '20px', 
                border: '1px solid #ddd', 
                borderRadius: '10px',
                backgroundColor: '#f9f9f9'
              }}>
                <h3>📸 Detección de Objetos</h3>
                <form onSubmit={handlePhotoSubmit}>
                  <input
                    id="photoInput"
                    type="file"
                    accept="image/*"
                    onChange={handleFileChange}
                    style={{
                      width: '100%',
                      padding: '10px',
                      margin: '10px 0',
                      border: '1px solid #ccc',
                      borderRadius: '5px'
                    }}
                  />
                  <button 
                    type="submit" 
                    className="action-btn"
                    style={{ width: '100%', marginTop: '10px' }}
                    disabled={isProcessing}
                  >
                    {isProcessing ? 'Procesando...' : 'Procesar con IA'}
                  </button>
                </form>
                {isProcessing && (
                  <div style={{
                    marginTop: '15px',
                    padding: '10px',
                    backgroundColor: '#e8f4fd',
                    color: '#007bff',
                    borderRadius: '5px',
                    textAlign: 'center'
                  }}>
                    🔄 Procesando imagen con YOLO...
                  </div>
                )}
                {photoResponse && (
                  <div style={{
                    marginTop: '15px',
                    padding: '10px',
                    backgroundColor: photoResponse.includes('❌') ? '#f8d7da' : '#d4edda',
                    color: photoResponse.includes('❌') ? '#721c24' : '#155724',
                    borderRadius: '5px',
                    whiteSpace: 'pre-line'
                  }}>
                    {photoResponse}
                  </div>
                )}
              </div>
            </div>

            {/* Instrucciones */}
            <div style={{ 
              marginTop: '30px', 
              padding: '20px', 
              border: '2px dashed #667eea', 
              borderRadius: '10px',
              backgroundColor: '#f8f9ff',
              textAlign: 'center'
            }}>
              <h3>📖 Instrucciones de Uso</h3>
              <div style={{ textAlign: 'left', maxWidth: '800px', margin: '0 auto' }}>
                <p><strong>1. Código QR para Móviles:</strong></p>
                <p>• Haz clic en "Mostrar Código QR" para generar el código</p>
                <p>• Escanea el código desde tu teléfono móvil</p>
                <p>• Usa la aplicación móvil para enviar datos o tomar fotos</p>
                
                <p style={{ marginTop: '15px' }}><strong>2. Desde esta interfaz:</strong></p>
                <p>• Envía datos de texto directamente</p>
                <p>• Sube imágenes para detección de objetos con IA</p>
                <p>• Verifica el estado del sistema y los logs</p>
                
                <p style={{ marginTop: '15px' }}><strong>3. Detección YOLO:</strong></p>
                <p>• El sistema usa inteligencia artificial para detectar objetos</p>
                <p>• Los resultados se guardan automáticamente</p>
                <p>• Puedes ver los detalles de cada detección</p>
              </div>
            </div>

            {/* Modal de logs */}
            {showLogs && (
              <div style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundColor: 'rgba(0,0,0,0.5)',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                zIndex: 1000
              }}>
                <div style={{
                  backgroundColor: 'white',
                  padding: '30px',
                  borderRadius: '10px',
                  maxWidth: '80%',
                  maxHeight: '80%',
                  overflow: 'auto',
                  minWidth: '500px'
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '20px' }}>
                    <h3>📋 Últimos Logs del Sistema</h3>
                    <button 
                      onClick={() => setShowLogs(false)}
                      style={{
                        background: '#dc3545',
                        color: 'white',
                        border: 'none',
                        padding: '5px 15px',
                        borderRadius: '5px',
                        cursor: 'pointer'
                      }}
                    >
                      ✕ Cerrar
                    </button>
                  </div>
                  
                  {logs.length === 0 ? (
                    <p>No hay logs disponibles</p>
                  ) : (
                    <div style={{ maxHeight: '400px', overflow: 'auto' }}>
                      {logs.slice(-10).reverse().map((log, index) => (
                        <div key={index} style={{
                          padding: '10px',
                          margin: '10px 0',
                          border: '1px solid #ddd',
                          borderRadius: '5px',
                          backgroundColor: log.type === 'photo_processing' ? '#e8f5e8' : '#f8f9fa'
                        }}>
                          <div><strong>Tiempo:</strong> {new Date(log.timestamp).toLocaleString()}</div>
                          <div><strong>Tipo:</strong> {log.type === 'photo_processing' ? '📸 Procesamiento de foto' : '📝 Datos de texto'}</div>
                          {log.data && <div><strong>Datos:</strong> {log.data}</div>}
                          {log.original_file && <div><strong>Archivo:</strong> {log.original_file}</div>}
                          {log.detections && log.detections.length > 0 && (
                            <div><strong>Detecciones:</strong> {log.detections.map(d => `${d.class} (${d.confidence}%)`).join(', ')}</div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            )}
          </section>
        </div>
      </div>
    </div>
  );
};

export default QR;
