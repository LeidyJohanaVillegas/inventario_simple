import React, { useState } from "react";
import ModalCrearLote from "./Modales/Lotes/ModalCrearLote";
import ModalEditarLote from "./Modales/Lotes/ModalEditarLote";
import { useSearch } from "../Components/common/Context/SearchContext";

const Lotes = ({ cambiarPagina }) => {
  const { searchTerm } = useSearch();

  const [lotes, setLotes] = useState([
    {
      id: "ORD-001",
      producto: "Mora",
      fechaIngreso: "2025-09-15",
      vencimiento: "2025-12-01",
      estado: "Activo",
      responsable: "Juan Pérez",
      ordenes: "ORD-MORA-12",
      insumos: "Cajas, Etiquetas",
    },
    {
      id: "ORD-002",
      producto: "Cacao",
      fechaIngreso: "2025-09-18",
      vencimiento: "2025-12-15",
      estado: "Inactivo",
      responsable: "María López",
      ordenes: "ORD-CACAO-08",
      insumos: "Sacos, Sellos",
    },
  ]);

  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isEditarOpen, setIsEditarOpen] = useState(false);
  const [modoEliminar, setModoEliminar] = useState(false);
  const [seleccionados, setSeleccionados] = useState([]);
  const [loteEditando, setLoteEditando] = useState(null);

  const abrirModal = () => setIsModalOpen(true);
  const cerrarModal = () => setIsModalOpen(false);

  const abrirEditar = (lote) => {
    setLoteEditando(lote);
    setIsEditarOpen(true);
  };
  const cerrarEditar = () => {
    setLoteEditando(null);
    setIsEditarOpen(false);
  };

  const guardarLote = (nuevoLote) => {
    const id = `ORD-${String(lotes.length + 1).padStart(3, "0")}`;

    setLotes([
      ...lotes,
      {
        id,
        producto: nuevoLote.producto,
        fechaIngreso: nuevoLote.fechaIngreso,
        vencimiento: nuevoLote.vencimiento,
        estado: nuevoLote.estado,
      },
    ]);
  };

  const guardarEdicion = (dataEditada) => {
    setLotes((prev) =>
      prev.map((l) =>
        l.id === loteEditando.id ? { ...l, ...dataEditada } : l
      )
    );
    cerrarEditar();
  };

  const toggleSeleccion = (id) => {
    setSeleccionados((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const manejarEliminar = () => {
    if (!modoEliminar) {
      setModoEliminar(true);
    } else {
      if (seleccionados.length > 0) {
        setLotes(lotes.filter((lote) => !seleccionados.includes(lote.id)));
        setSeleccionados([]);
      }
      setModoEliminar(false);
    }
  };

  // 🔎 Filtrado por searchTerm
  const filtrados = lotes.filter(lote =>
    Object.values(lote).some(val =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Lotes</h2>
            <div className="table-grid lotes-grid">
              <div className="grid-header">ID</div>
              <div className="grid-header">Producto</div>
              <div className="grid-header">Fecha</div>
              <div className="grid-header">Vencimiento</div>
              <div className="grid-header">Estado</div>
              <div className="grid-header">Acciones</div>

              {filtrados.map((lote) => (
                <div className="grid-row" key={lote.id}>
                  <div className="grid-cell">{lote.id}</div>
                  <div className="grid-cell">{lote.producto}</div>
                  <div className="grid-cell">{lote.fechaIngreso}</div>
                  <div className="grid-cell">{lote.vencimiento}</div>
                  <div className="grid-cell">{lote.estado}</div>
                  <div className="grid-cell">
                    {modoEliminar ? (
                      <input
                        type="checkbox"
                        checked={seleccionados.includes(lote.id)}
                        onChange={() => toggleSeleccion(lote.id)}
                      />
                    ) : (
                      <button
                        className="action-btn"
                        onClick={() => abrirEditar(lote)}
                      >
                        Editar
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <div className="btn-container-3">
              <button className="btn-components" onClick={abrirModal}>
                Crear Lote
              </button>
              <button
                className="btn-components"
                onClick={() => cambiarPagina("materiales")}
              >
                Materiales
              </button>
              <button
                className="btn-components"
                onClick={manejarEliminar}
                disabled={lotes.length === 0}
              >
                {modoEliminar ? "Confirmar" : "Eliminar"}
              </button>
            </div>
          </section>
        </div>
      </div>

      {/* Modal crear */}
      <ModalCrearLote
        isOpen={isModalOpen}
        onClose={cerrarModal}
        onGuardar={guardarLote}
      />

      <ModalEditarLote
        isOpen={isEditarOpen}
        onClose={cerrarEditar}
        onGuardar={guardarEdicion}
        lote={loteEditando}
      />
    </div>
  );
};

export default Lotes;
