import React, { useState } from "react";
import ModalRegistrarProveedor from "./Modales/Proveedores/ModalRegistrarProveedor";
import ModalInformeProveedor from "./Modales/Proveedores/ModalInformeProveedor"; 
import { useSearch } from "../Components/common/Context/SearchContext";

const Proveedores = () => {
  const { searchTerm } = useSearch();

  const [modalOpen, setModalOpen] = useState(false);
  const [modalInformeOpen, setModalInformeOpen] = useState(false);
  const [proveedorSeleccionado, setProveedorSeleccionado] = useState(null);

  const [proveedores, setProveedores] = useState([
    {
      nombre: "Juan Pérez",
      telefono: "3203828345",
      email: "juan@example.com",
      direccion: "Av. Siempre Viva 123, Ciudad",
    },
    {
      nombre: "María García",
      telefono: "3192374583",
      email: "maria@example.com",
      direccion: "Calle Falsa 456, Pueblo",
    },
  ]);

  // Estado para activar modo eliminar
  const [modoEliminar, setModoEliminar] = useState(false);
  const [seleccionados, setSeleccionados] = useState([]);

  const abrirModal = () => setModalOpen(true);
  const cerrarModal = () => setModalOpen(false);

  const guardarProveedor = (nuevoProveedor) => {
    setProveedores([...proveedores, nuevoProveedor]);
  };

  const abrirInforme = (proveedor) => {
    setProveedorSeleccionado({
      proveedor: proveedor.nombre,
      periodo: "01/08/2025",
      productos: [
        { nombre: "Harina", cantidad: "500 kg" },
        { nombre: "Azúcar", cantidad: "100 kg" },
      ],
      entregas: "95%",
      tiempo: "3 días",
    });
    setModalInformeOpen(true);
  };

  const cerrarInforme = () => {
    setProveedorSeleccionado(null);
    setModalInformeOpen(false);
  };

  // Manejar check de selección
  const toggleSeleccion = (index) => {
    if (seleccionados.includes(index)) {
      setSeleccionados(seleccionados.filter((i) => i !== index));
    } else {
      setSeleccionados([...seleccionados, index]);
    }
  };

  // Eliminar seleccionados
  const eliminarSeleccionados = () => {
    const nuevos = proveedores.filter((_, i) => !seleccionados.includes(i));
    setProveedores(nuevos);
    setSeleccionados([]);
    setModoEliminar(false); 
  };

  // 🔎 Filtrado por searchTerm (nombre, teléfono, email o dirección)
  const filtrados = proveedores.filter((proveedor) =>
    Object.values(proveedor).some((val) =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Proveedores</h2>
            <div className="table-grid ordenes-grid">
              <div className="grid-header">Nombre</div>
              <div className="grid-header">Teléfono</div>
              <div className="grid-header">Email</div>
              <div className="grid-header">Dirección</div>
              <div className="grid-header">Acciones</div>

              {filtrados.map((proveedor, index) => (
                <div className="grid-row" key={index}>
                  <div className="grid-cell">{proveedor.nombre}</div>
                  <div className="grid-cell">{proveedor.telefono}</div>
                  <div className="grid-cell">{proveedor.email}</div>
                  <div className="grid-cell">{proveedor.direccion}</div>
                  <div className="grid-cell">
                    {modoEliminar ? (
                      <input
                        type="checkbox"
                        checked={seleccionados.includes(index)}
                        onChange={() => toggleSeleccion(index)}
                      />
                    ) : (
                      <button
                        className="action-btn"
                        onClick={() => abrirInforme(proveedor)}
                      >
                        Ver
                      </button>
                    )}
                  </div>
                </div>
              ))}
            </div>

            <div className="btn-container">
              <button className="btn-components" onClick={abrirModal}>
                Registrar
              </button>

              {modoEliminar ? (
                <div className="btn-confirm-container">
                  <button
                    className="btn-components"
                    onClick={eliminarSeleccionados}
                  >
                    Confirmar
                  </button>
                  <button
                    className="btn-components"
                    onClick={() => setModoEliminar(false)}
                  >
                    Cancelar
                  </button>
                </div>
              ) : (
                <button
                  className="btn-components"
                  onClick={() => setModoEliminar(true)}
                >
                  Eliminar
                </button>
              )}
            </div>
          </section>
        </div>
      </div>

      <ModalRegistrarProveedor
        isOpen={modalOpen}
        onClose={cerrarModal}
        onGuardar={guardarProveedor}
      />

      {proveedorSeleccionado && (
        <ModalInformeProveedor
          isOpen={modalInformeOpen}
          onClose={cerrarInforme}
          informe={proveedorSeleccionado}
        />
      )}
    </div>
  );
};

export default Proveedores;
