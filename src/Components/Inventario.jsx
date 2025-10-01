import React, { useState } from "react";
import ModalEntradas from "./Modales/Inventario/ModalEntradas";
import ModalSalidas from "./Modales/Inventario/ModalSalidas";
import { useSearch } from "../Components/common/Context/SearchContext";

const Inventario = () => {
  const { searchTerm } = useSearch();

  const [inventario, setInventario] = useState([
    { producto: "Producto A", categoria: "Medicamento", stock: 150, vencimiento: "2023-12-31", estado: "Activo" },
    { producto: "Producto B", categoria: "Material", stock: 75, vencimiento: "2024-06-30", estado: "Activo" },
  ]);

  const [modalEntradasOpen, setModalEntradasOpen] = useState(false);
  const [modalSalidasOpen, setModalSalidasOpen] = useState(false);

  // 🔎 Filtrar usando searchTerm
  const filtrados = inventario.filter(item =>
    Object.values(item).some(val =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  const handleGuardarEntrada = (data) => {
    const index = inventario.findIndex(item => item.producto === data.producto);
    if (index !== -1) {
      const newStock = inventario[index].stock + Number(data.cantidad);
      const newVencimiento =
        data.fechaVencimiento > inventario[index].vencimiento
          ? data.fechaVencimiento
          : inventario[index].vencimiento;

      const updatedItem = {
        ...inventario[index],
        stock: newStock,
        vencimiento: newVencimiento,
      };
      const newInventario = [...inventario];
      newInventario[index] = updatedItem;
      setInventario(newInventario);
    } else {
      setInventario([
        ...inventario,
        {
          producto: data.producto,
          categoria: "Medicamento",
          stock: Number(data.cantidad),
          vencimiento: data.fechaVencimiento,
          estado: "Activo",
        },
      ]);
    }
  };

  const handleGuardarSalida = (data) => {
    const index = inventario.findIndex(item => item.producto === data.producto);
    if (index !== -1) {
      const newStock = inventario[index].stock - Number(data.cantidad);
      if (newStock < 0) {
        alert("No hay suficiente stock para esta salida");
        return;
      }
      const updatedItem = {
        ...inventario[index],
        stock: newStock,
      };
      const newInventario = [...inventario];
      newInventario[index] = updatedItem;
      setInventario(newInventario);
    } else {
      alert("Producto no encontrado en inventario");
    }
  };

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Inventario</h2>
            <div className="table-grid inventario-grid">
              <div className="grid-header">Producto</div>
              <div className="grid-header">Categoría</div>
              <div className="grid-header">Stock</div>
              <div className="grid-header">Vencimiento</div>
              <div className="grid-header">Estado</div>

              {filtrados.map((item, i) => ( // ✅ usar filtrados aquí
                <React.Fragment key={i}>
                  <div className="grid-cell">{item.producto}</div>
                  <div className="grid-cell">{item.categoria}</div>
                  <div className="grid-cell">{item.stock}</div>
                  <div className="grid-cell">{item.vencimiento}</div>
                  <div className="grid-cell">{item.estado}</div>
                </React.Fragment>
              ))}
            </div>

            <div className="btn-container">
              <button
                className="btn-components"
                onClick={() => setModalEntradasOpen(true)}
              >
                Entradas
              </button>
              <button
                className="btn-components"
                onClick={() => setModalSalidasOpen(true)}
              >
                Salidas
              </button>
            </div>

            <ModalEntradas
              isOpen={modalEntradasOpen}
              onClose={() => setModalEntradasOpen(false)}
              onGuardar={handleGuardarEntrada}
            />

            <ModalSalidas
              isOpen={modalSalidasOpen}
              onClose={() => setModalSalidasOpen(false)}
              onGuardar={handleGuardarSalida}
            />
          </section>
        </div>
      </div>
    </div>
  );
};

export default Inventario;
