import React, { useState } from "react";
import ModalDescargar from "./ModalDescargar"; 
import "./modalreportes.css";

const ModalHistorialReportes = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  // Datos ficticios
  const historial = [
    { fecha: "2023-09-28", accion: "Edición", detalle: "Se editó el producto Cacao", responsable: "Aprendiz A" },
    { fecha: "2023-09-28", accion: "Eliminación", detalle: "Se eliminó el lote L-005", responsable: "Aprendiz B" },
    { fecha: "2023-09-27", accion: "Stock bajo", detalle: "Harina < 10kg", responsable: "Sistema" },
    { fecha: "2023-09-26", accion: "Nuevo lote", detalle: "L-010 creado", responsable: "Aprendiz C" },
    { fecha: "2023-09-26", accion: "Ingreso", detalle: "Se subió producto Azúcar 100kg", responsable: "Aprendiz D" },
  ];


  const [filtroFecha, setFiltroFecha] = useState("");
  const [filtroAccion, setFiltroAccion] = useState("Todos");
  const [openModalDescargar, setOpenModalDescargar] = useState(false);


  const historialFiltrado = historial.filter((item) => {
    const coincideFecha = filtroFecha ? item.fecha === filtroFecha : true;
    const coincideAccion = filtroAccion === "Todos" ? true : item.accion === filtroAccion;
    return coincideFecha && coincideAccion;
  });

  return (
    <div className="historial-overlay">
      <div className="historial-container">
        

        <div className="historial-header">
          <h2>Historial</h2>
          <button className="historial-close" onClick={onClose}>
            ×
          </button>
        </div>

        {/* Filtros */}
        <div className="historial-body">
          <div className="historial-row">
            <label>Fecha:</label>
            <input
              type="date"
              className="historial-input"
              value={filtroFecha}
              onChange={(e) => setFiltroFecha(e.target.value)}
            />
          </div>
          <div className="historial-row">
            <label>Acción:</label>
            <select
              className="historial-input"
              value={filtroAccion}
              onChange={(e) => setFiltroAccion(e.target.value)}
            >
              <option value="Todos">Todos</option>
              <option value="Edición">Edición</option>
              <option value="Eliminación">Eliminación</option>
              <option value="Stock bajo">Stock bajo</option>
              <option value="Nuevo lote">Nuevo lote</option>
              <option value="Ingreso">Ingreso</option>
            </select>
          </div>

          {/* Tabla */}
          <div className="historial-tabla-contenedor">
            <table>
              <thead>
                <tr>
                  <th>Fecha</th>
                  <th>Acción</th>
                  <th>Detalle</th>
                  <th>Responsable</th>
                </tr>
              </thead>
              <tbody>
                {historialFiltrado.length > 0 ? (
                  historialFiltrado.map((item, index) => (
                    <tr key={index}>
                      <td>{item.fecha}</td>
                      <td>{item.accion}</td>
                      <td>{item.detalle}</td>
                      <td>{item.responsable}</td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan="4" style={{ textAlign: "center", padding: "10px" }}>
                      No se encontraron registros
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="historial-footer">
          <button className="btn-cerrar" onClick={onClose}>
            Cerrar
          </button>
          <button className="btn-descargar" onClick={() => setOpenModalDescargar(true)}>
            Descargar Reporte
          </button>
        </div>
      </div>


      <ModalDescargar
        isOpen={openModalDescargar}
        onClose={() => setOpenModalDescargar(false)}
        data={historialFiltrado}   
      />
    </div>
  );
};

export default ModalHistorialReportes;
