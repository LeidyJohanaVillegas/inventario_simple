import React, { useState } from "react";

const Materiales = () => {
  const [materiales] = useState([
    {
      nombre: "Cartón",
      tipo: "Empaque",
      cantidad: "200 unidades",
      asignacion: "Pepito",
    },
    {
      nombre: "Plástico",
      tipo: "Botellas",
      cantidad: "500 kg",
      asignacion: "Gyret",
    },
    {
      nombre: "Vidrio",
      tipo: "Botellas",
      cantidad: "100 kg",
      asignacion: "JJ",
    },
  ]);

  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">
          <section className="inventario-section">
            <h2>Materiales</h2>
            <div className="table-grid inventario-grid">
              <div className="grid-header">Nombre</div>
              <div className="grid-header">Tipo</div>
              <div className="grid-header">Cantidad</div>
              <div className="grid-header">Asignación</div> {/* esto son las asignacion y es de la tabla de materiales al json de id usuario */}
              <div className="grid-header">Acciones</div>

              {materiales.map((mat, index) => (
                <div className="grid-row" key={index}>
                  <div className="grid-cell">{mat.nombre}</div>
                  <div className="grid-cell">{mat.tipo}</div>
                  <div className="grid-cell">{mat.cantidad}</div>
                  <div className="grid-cell">{mat.asignacion}</div>
                  <div className="grid-cell">
                    <button className="action-btn">Ver</button>

                  </div>
                </div>
              ))}
            </div>

            <div className="btn-container">
              <button className="btn-components">Agregar Material</button>
              <button className="btn-components">Eliminar</button>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default Materiales;
