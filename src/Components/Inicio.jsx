import '../../src/App.css'

const Inicio = ({ cambiarPagina }) => {
  return (
    <div className="container">
      <div className="main-content">
        <div className="content-area">

          {/* Inventario */}
          <section className="inventario-section ordenes-section">
            <h2>Inventario</h2>
            <div className="table-grid inventario-grid">
              <div className="grid-header">Nombre</div>
              <div className="grid-header">Ingreso</div>
              <div className="grid-header">Vencimiento</div>
              <div className="grid-header">Proveedor</div>
              <div className="grid-header">...</div>

              <div className="grid-row">
                <div className="grid-cell">Producto A</div>
                <div className="grid-cell">Perecederos</div>
                <div className="grid-cell">20/05/03</div>
                <div className="grid-cell">Coca-cola</div>
                <div className="grid-cell">
                  <button 
                    className="action-btn" 
                    onClick={() => cambiarPagina("inventario")}
                  >
                    Ir
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* Reportes */}
          <section className="ordenes-section">
            <h2>Reportes</h2>
            <div className="table-grid ordenes-grid">
              <div className="grid-header">Fecha</div>
              <div className="grid-header">Tipo</div>
              <div className="grid-header">Lote</div>
              <div className="grid-header">Producto</div>
              <div className="grid-header">...</div>

              <div className="grid-row">
                <div className="grid-cell">Juan Pérez</div>
                <div className="grid-cell">Bajo</div>
                <div className="grid-cell">Wasaaaaaaaa</div>
                <div className="grid-cell">Activo</div>
                <div className="grid-cell">
                  <button 
                    className="action-btn"
                    onClick={() => cambiarPagina("reportes")}
                  >
                    Ir
                  </button>
                </div>
              </div>
            </div>
          </section>

          {/* Órdenes */}
          <section className="ordenes-section">
            <h2>Órdenes</h2>
            <div className="table-grid ordenes-grid">
              <div className="grid-header">Producto</div>
              <div className="grid-header">Responsable</div>
              <div className="grid-header">Cantidad</div>
              <div className="grid-header">Estado</div>
              <div className="grid-header">...</div>

              <div className="grid-row">
                <div className="grid-cell">Coca-cola</div>
                <div className="grid-cell">Juan Pérez</div>
                <div className="grid-cell">100</div>
                <div className="grid-cell">Activo</div>
                <div className="grid-cell">
                  <button 
                    className="action-btn"
                    onClick={() => cambiarPagina("ordenes")}
                  >
                    Ir
                  </button>
                </div>
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
};

export default Inicio;
