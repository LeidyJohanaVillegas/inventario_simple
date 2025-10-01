import React, { useState } from "react";
import ModalCrearOrden from "./Modales/Ordenes/ModalCrearOrden";
import HistorialModal from "./Modales/Ordenes/ModalHistorialOrdenes";
import { useSearch } from "../Components/common/Context/SearchContext";

const Ordenes = () => {
  const { searchTerm } = useSearch();

  const [modalOpen, setModalOpen] = useState(false);
  const [historialOpen, setHistorialOpen] = useState(false);

  const [ordenes, setOrdenes] = useState([
    {
      id: "ORD-001",
      producto: "Cacao",
      responsable: "Juan Pérez",
      cantidad: 100,
      estado: "Pendiente",
    },
    {
      id: "ORD-002",
      producto: "Mora",
      responsable: "María García",
      cantidad: 50,
      estado: "Completado",
    },
  ]);

  const handleGuardarOrden = (nuevaOrden) => {
    const nuevaID = `ORD-${(ordenes.length + 1).toString().padStart(3, "0")}`;

    const nuevaOrdenCompleta = {
      id: nuevaID,
      producto: nuevaOrden.producto,
      responsable: nuevaOrden.responsable,
      cantidad: nuevaOrden.cantidad,
      estado: nuevaOrden.estado || "Pendiente",
    };

    setOrdenes([...ordenes, nuevaOrdenCompleta]);
  };

  // 🔎 Filtrado por searchTerm
  const filtrados = ordenes.filter((orden) =>
    Object.values(orden).some((val) =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Órdenes</h2>
            <div className="table-grid ordenes-grid">
              <div className="grid-header">Producto</div>
              <div className="grid-header">Responsable</div>
              <div className="grid-header">Cantidad</div>
              <div className="grid-header">Estado</div>
              <div className="grid-header">Acciones</div>

              {filtrados.map((orden) => (
                <div className="grid-row" key={orden.id}>
                  <div className="grid-cell">{orden.producto}</div>
                  <div className="grid-cell">{orden.responsable}</div>
                  <div className="grid-cell">{orden.cantidad}</div>
                  <div className="grid-cell">{orden.estado}</div>
                  <div className="grid-cell">
                    <button className="action-btn">Editar</button>
                  </div>
                </div>
              ))}
            </div>

            <div className="btn-container">
              <button
                className="btn-components"
                onClick={() => setModalOpen(true)}
              >
                Crear Orden
              </button>
              <button
                className="btn-components"
                onClick={() => setHistorialOpen(true)}
              >
                Historial
              </button>
            </div>
          </section>
        </div>
      </div>

      {/* Modal Crear Orden */}
      <ModalCrearOrden
        isOpen={modalOpen}
        onClose={() => setModalOpen(false)}
        onGuardar={handleGuardarOrden}
      />

      {/* Modal Historial */}
      <HistorialModal
        isOpen={historialOpen}
        onClose={() => setHistorialOpen(false)}
      />
    </div>
  );
};

export default Ordenes;
