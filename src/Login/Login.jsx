import React, { useState } from "react";
import "./login.css";
import fondoLogin from "../assets/fondo-login.jpg";
import ingresar from "../assets/icons/ingresar.png";

const Login = ({ cambiarPagina, onLoginSuccess }) => {
  const [documentoID, setDocumentoID] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setLoading(true);

    // 🔹 Por ahora omitimos autenticación
    setTimeout(() => {
      setLoading(false);
      onLoginSuccess(); // Entrar directamente
    }, 800); // Simulación de espera
  };

  return (
    <div className="login-page-container">
      <div className="login-compact-container">
        <div className="login-form-section">
          <h2 className="login-title">Inicio de Sesión</h2>
          <form onSubmit={handleSubmit} className="login-form">
            <input
              type="text"
              placeholder="Documento ID"
              value={documentoID}
              onChange={(e) => setDocumentoID(e.target.value)}
              disabled={loading}
              className="login-input"
              required
            />
            <input
              type="password"
              placeholder="Contraseña"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={loading}
              className="login-input"
              required
            />
            <button 
              type="submit" 
              className="login-button"
              disabled={loading}
              
            >
              {loading ? 'Ingresando...' : 'Ingresar'}
              <img src={ingresar}/>
              
            </button>
          </form>
          <p className="login-register-text">
            ¿No tienes cuenta?{" "}
            <button
              type="button"
              onClick={cambiarPagina}
              className="login-register-link"
            >
              Regístrate aquí
            </button>
          </p>
        </div>
        <div className="login-image-section">
          <img
            src={fondoLogin}
            alt="Fondo login"
            className="login-image"
          />
        </div>
      </div>
    </div>
  );
};

export default Login;
