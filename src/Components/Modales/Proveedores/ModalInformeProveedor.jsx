import React from "react";


const ModalInformeProveedor = ({ isOpen, onClose, informe }) => {
  if (!isOpen) return null;

  return (
    <div className="descargar-overlay">
      <div className="descargar-container">
        {/* Header */}
        <div className="descargar-header">
          <h2>Informe Automático a Proveedor</h2>
          <button className="descargar-close" onClick={onClose}>
            ×
          </button>
        </div>

        {/* Body */}
        <div className="descargar-body">
          <p>
            <strong>Proveedor:</strong> {informe.proveedor}
          </p>
          <p>
            <strong>Periodo de orden:</strong> {informe.periodo}
          </p>

          <hr />

          <div>
            <strong>Productos solicitados:</strong>
            <ul>
              {informe.productos.map((p, index) => (
                <li key={index}>
                  {p.nombre}: {p.cantidad}
                </li>
              ))}
            </ul>
          </div>

          <hr />

          <p>
            <strong>Entregas cumplidas:</strong> {informe.entregas}
          </p>
          <p>
            <strong>Tiempo promedio de entrega:</strong> {informe.tiempo}
          </p>
        </div>

        {/* Footer */}
        <div className="descargar-footer">
          <button className="btn-formato">Exportar PDF</button>
          <button className="btn-cerrar">Editar</button>
        </div>
      </div>
    </div>
  );
};

export default ModalInformeProveedor;
