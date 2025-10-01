import React, { useState, useEffect } from "react";
//import axios from "axios";
import ModalDescargar from "../Components/Modales/Reportes/ModalDescargar";
import Historial from "../Components/Modales/Reportes/ModalHistorialReportes";
import { useSearch } from "../Components/common/Context/SearchContext";

const Reportes = () => {
  const { searchTerm } = useSearch();

  const [reportes, setReportes] = useState([]); 
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [isDescargarOpen, setIsDescargarOpen] = useState(false);
  const [isHistorialOpen, setIsHistorialOpen] = useState(false);

  useEffect(() => {
    const fetchReportes = async () => {
      try {
        // 🔹 Simulación temporal
        const dataFicticia = [
          { fecha: "2023-10-10", tipo: "Stock", lote: "Lote - 001", producto: "Cacao", cantidad: "15kg", responsable: "Juanito" },
          { fecha: "2023-10-10", tipo: "Stock", lote: "Lote - 001", producto: "Azúcar", cantidad: "200kg", responsable: "Juanita" },
          { fecha: "2023-10-11", tipo: "Entrada", lote: "Lote - 002", producto: "Harina", cantidad: "50kg", responsable: "Carlos" },
        ];

        setReportes(dataFicticia);
      } catch (err) {
        console.error("❌ Error cargando reportes:", err);
        setError("Error al cargar los reportes");
      } finally {
        setLoading(false);
      }
    };

    fetchReportes();
  }, []);

  // 🔎 Filtrado por searchTerm (fecha, tipo, lote, producto, cantidad o responsable)
  const filtrados = reportes.filter((r) =>
    Object.values(r).some((val) =>
      String(val).toLowerCase().includes(searchTerm.toLowerCase())
    )
  );

  if (loading) return <p>Cargando reportes...</p>;
  if (error) return <p>{error}</p>;

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Reportes</h2>

            <div className="table-grid lotes-grid">
              <div className="grid-header">Fecha</div>
              <div className="grid-header">Tipo</div>
              <div className="grid-header">Lote</div>
              <div className="grid-header">Producto</div>
              <div className="grid-header">Cantidad</div>
              <div className="grid-header">Responsable</div>

              {/* Filas dinámicas filtradas */}
              {filtrados.map((r, i) => (
                <div className="grid-row" key={i}>
                  <div className="grid-cell">{r.fecha}</div>
                  <div className="grid-cell">{r.tipo}</div>
                  <div className="grid-cell">{r.lote}</div>
                  <div className="grid-cell">{r.producto}</div>
                  <div className="grid-cell">{r.cantidad}</div>
                  <div className="grid-cell">{r.responsable}</div>
                </div>
              ))}
            </div>

            <div className="btn-container">
              <button
                className="btn-components"
                onClick={() => setIsDescargarOpen(true)}
              >
                Descargar
              </button>
              <button
                className="btn-components"
                onClick={() => setIsHistorialOpen(true)}
              >
                Historial
              </button>
            </div>
          </section>
        </div>
      </div>

      <ModalDescargar
        isOpen={isDescargarOpen}
        onClose={() => setIsDescargarOpen(false)}
      />

      <Historial
        isOpen={isHistorialOpen}
        onClose={() => setIsHistorialOpen(false)}
      />
    </div>
  );
};

export default Reportes;
