import { useState } from "react";
import Calendar from "react-calendar"; 
import "react-calendar/dist/Calendar.css";
import "../modal.css"; 
import { useModal } from "../Usuarios/ModalContext"
import salir from "../../../assets/icons/ingresar.png"
import registrar from "../../../assets/icons/registrar.png"
import gestion from "../../../assets/icons/gestion.png"
import manual from "../../../assets/icons/manual.png"

function ModalMenu({ isOpen, onClose, cambiarPagina, setIsLoggedIn  }) {
  const [date, setDate] = useState(new Date());
  const { closeModal } = useModal();

  const irAGestionUsuarios = () => {
  cambiarPagina("usuarios"); 
  closeModal(); 
  };

    const irRegistro = () => {
    setIsLoggedIn(false);
    cambiarPagina("registro"); 
    closeModal(); 
  };

    const irLogin = () => {
    setIsLoggedIn(false);
    cambiarPagina("login"); 
    closeModal(); 
  };
  
  if (!isOpen) return null;

  return (
    <div className="menu-modal-overlay" onClick={onClose}>
      <div className="menu-modal-container" onClick={(e) => e.stopPropagation()}>
        <button className="menu-close-btn" onClick={closeModal}>×</button>
        
        <div className="menu-modal-logo"></div>

        <h2 className="menu-modal-title">Admin</h2>

        <div className="menu-top-buttons">
          <button className="menu-btn" onClick={irAGestionUsuarios}>
            <img src={gestion} alt="icono gestion" className="menu-img" />
            Gestión Usuarios
          </button>
          <button className="menu-btn">
            Manual Ayuda
            <img src={manual} alt="icono manual" className="menu-img" />
          </button>
        </div>

        <div className="menu-calendar-wrapper">
          <Calendar
            onChange={setDate}
            value={date}
            tileContent={({ date }) =>
              date.getDate() === 24 ? <span className="menu-event-dot"></span> : null
            }
          />
        </div>

        <div className="menu-bottom-buttons">
          <button className="menu-btn" onClick={irRegistro}>
            <img src={registrar} alt="icono registrar" className="menu-img"  />
            Registrar Usuario
          </button>
          <button className="menu-btn" onClick={irLogin}>
            Cerrar Sesión
            <img src={salir} alt="icono salir" className="menu-img" />
          </button>
        </div>
      </div>
    </div>
  );
}

export default ModalMenu;
