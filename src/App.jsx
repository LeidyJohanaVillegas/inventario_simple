// App.jsx
import { useState } from "react";
import { ModalProvider } from "../src/Components/Modales/Usuarios/ModalContext";
import { SearchProvider } from "./Components/common/Context/SearchContext"; 

import Login from "./Components/Login/Login";
import Registro from "./Components/Login/Register";
import Inicio from "./Components/Inicio";
import Sidebar from "./Components/common/Sidebar";
import Inventario from "../src/Components/Inventario";
import Ordenes from "../src/Components/Ordenes";
import Lotes from "../src/Components/Lotes";
import Proveedores from "../src/Components/Proveedores";  
import Reportes from "../src/Components/Reportes";
import Header from "../src/Components/common/Header";
import GestionUsuarios from "../src/Components/Modales/Usuarios/GestionUsuarios/GestionUsuarios";
import Materiales from "./Components/Materiales";

import "../src/Components/common/common.css";

function App() {
  const [paginaActual, setPaginaActual] = useState("login");
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  const handleLoginSuccess = () => {
    setIsLoggedIn(true);
    setPaginaActual("inicio");
  };

  return (
    <ModalProvider cambiarPagina={setPaginaActual} setIsLoggedIn={setIsLoggedIn}>
      <SearchProvider> 
        <div>
          {!isLoggedIn && paginaActual === "login" && (
            <Login
              onLoginSuccess={handleLoginSuccess}
              cambiarPagina={() => setPaginaActual("registro")}
            />
          )}

          {!isLoggedIn && paginaActual === "registro" && (
            <Registro cambiarPagina={() => setPaginaActual("login")} />
          )}

          {isLoggedIn && (
            <div className="app-container">
              <Sidebar paginaActual={paginaActual} cambiarPagina={setPaginaActual} />
              
              <Header />  

              <div className="main-content">
                {paginaActual === "inventario" && <Inventario />}
                {paginaActual === "ordenes" && <Ordenes />}
                {paginaActual === "lotes" && <Lotes cambiarPagina={setPaginaActual} />}
                {paginaActual === "proveedores" && <Proveedores />}
                {paginaActual === "reportes" && <Reportes />}
                {paginaActual === "usuarios" && <GestionUsuarios />}
                {paginaActual === "materiales" && <Materiales />}
                {paginaActual === "inicio" && <Inicio cambiarPagina={setPaginaActual} />}
              </div>
            </div>
          )}
        </div>
      </SearchProvider>
    </ModalProvider>
  );
}

export default App;
