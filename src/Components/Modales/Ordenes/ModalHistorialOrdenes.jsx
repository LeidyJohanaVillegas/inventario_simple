import React, { useState, useEffect } from "react";
import "./historial.css";
// import axios from "axios";  // 👈 para cuando conectes con backend

function HistorialModal({ isOpen, onClose }) {
  const [ordenes, setOrdenes] = useState([]);
  const [filtroFecha, setFiltroFecha] = useState("");
  const [filtroResponsable, setFiltroResponsable] = useState("Todos");

  // Datos ficticios iniciales
  useEffect(() => {
    const datosFicticios = [
      { id: 1, fecha: "2025-09-20", responsable: "Juan Pérez", cantidad: 100, estado: "Pendiente" },
      { id: 2, fecha: "2025-09-21", responsable: "María García", cantidad: 50, estado: "Completado" },
      { id: 3, fecha: "2025-09-22", responsable: "Pedro López", cantidad: 70, estado: "En proceso" },
      { id: 4, fecha: "2025-09-23", responsable: "Ana Torres", cantidad: 30, estado: "Cancelado" },
    ];
    setOrdenes(datosFicticios);

    // 🔗 Ejemplo de cómo se conectaría con fetch o axios:
    /*
    axios.get("http://localhost:4000/api/ordenes/historial")
      .then(res => setOrdenes(res.data))
      .catch(err => console.error(err));
    */
  }, []);

  if (!isOpen) return null;

  // 🔎 Filtrar por fecha y responsable
  const ordenesFiltradas = ordenes.filter((orden) => {
    const coincideFecha = filtroFecha ? orden.fecha === filtroFecha : true;
    const coincideResponsable =
      filtroResponsable === "Todos" || orden.responsable === filtroResponsable;

    return coincideFecha && coincideResponsable;
  });

  return (
    <div className="historial-overlay">
      <div className="historial-container">
        {/* Header */}
        <div className="historial-header">
          <h2>Historial</h2>
          <button className="historial-close-btn" onClick={onClose}>
            X
          </button>
        </div>

        {/* Filtros */}
        <div className="historial-filtros">
          <div className="historial-filtro-item">
            <label>Fecha:</label>
            <input
              type="date"
              value={filtroFecha}
              onChange={(e) => setFiltroFecha(e.target.value)}
            />
          </div>

          <div className="historial-filtro-item">
            <label>Responsable:</label>
            <select
              value={filtroResponsable}
              onChange={(e) => setFiltroResponsable(e.target.value)}
            >
              <option>Todos</option>
              {/* dinámico: genera opciones según responsables únicos */}
              {[...new Set(ordenes.map((o) => o.responsable))].map((resp) => (
                <option key={resp}>{resp}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Tabla */}
        <div className="historial-tabla">
          <table>
            <thead>
              <tr>
                <th>Fecha</th>
                <th>Responsable</th>
                <th>Cantidad</th>
                <th>Estado</th>
              </tr>
            </thead>
            <tbody>
              {ordenesFiltradas.length > 0 ? (
                ordenesFiltradas.map((orden) => (
                  <tr key={orden.id}>
                    <td>{orden.fecha}</td>
                    <td>{orden.responsable}</td>
                    <td>{orden.cantidad}</td>
                    <td>{orden.estado}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan="4" style={{ textAlign: "center", color: "#888" }}>
                    No hay registros para los filtros seleccionados
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

export default HistorialModal;
