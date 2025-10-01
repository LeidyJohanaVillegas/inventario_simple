import "./common.css";

import iconInicio from "../../assets/icons/inicio.png";
import iconInventario from "../../assets/icons/inventario.png";
import iconOrdenes from "../../assets/icons/ordenes.png";
import iconLotes from "../../assets/icons/lotes.png";
import iconProveedores from "../../assets/icons/proveedores.png";
import iconReportes from "../../assets/icons/reportes.png";
import logo from "../../../logo.png"; 

const Sidebar = ({ paginaActual, cambiarPagina }) => {
  return (
    <div className="sidebar">
      
        <div className="sidebar-logo">
          <img src={logo} alt="Logo" className="logo" />
        </div>

      <ul>
        <li
          onClick={() => cambiarPagina("inicio")}
          className={paginaActual === "inicio" ? "active" : ""}
        >
          <img src={iconInicio} alt="Inicio" className="icon" />
          <span>Inicio</span>
        </li>
        <li
          onClick={() => cambiarPagina("inventario")}
          className={paginaActual === "inventario" ? "active" : ""}
        >
          <img src={iconInventario} alt="Inventario" className="icon" />
          <span>Inventario</span>
        </li>
        <li
          onClick={() => cambiarPagina("ordenes")}
          className={paginaActual === "ordenes" ? "active" : ""}
        >
          <img src={iconOrdenes} alt="Órdenes" className="icon" />
          <span>Órdenes</span>
        </li>
        <li
          onClick={() => cambiarPagina("lotes")}
          className={paginaActual === "lotes" ? "active" : ""}
        >
          <img src={iconLotes} alt="Lotes" className="icon" />
          <span>Lotes</span>
        </li>
        <li
          onClick={() => cambiarPagina("proveedores")}
          className={paginaActual === "proveedores" ? "active" : ""}
        >
          <img src={iconProveedores} alt="Proveedores" className="icon" />
          <span>Proveedores</span>
        </li>
        <li
          onClick={() => cambiarPagina("reportes")}
          className={paginaActual === "reportes" ? "active" : ""}
        >
          <img src={iconReportes} alt="Reportes" className="icon" />
          <span>Reportes</span>
        </li>
      </ul>
    </div>
  );
};

export default Sidebar;
