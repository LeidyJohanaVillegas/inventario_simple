import React, { useState } from "react";
import "./login.css";
import fondoLogin from "../../../src/assets/fondo-login.jpg";
import registrar from "../../../src/assets/icons/registrar.png"

const Register = ({ cambiarPagina }) => {
  const [formData, setFormData] = useState({
    usuario: "",
    cargo: "",
    tipoDocumento: "",
    documentoID: "",
    password: "",
    repeatPassword: "",
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value,
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setSuccess("");

    // Validaciones
    if (formData.password !== formData.repeatPassword) {
      setError("Las contraseñas no coinciden");
      setLoading(false);
      return;
    }

    if (formData.password.length < 6) {
      setError("La contraseña debe tener al menos 6 caracteres");
      setLoading(false);
      return;
    }

    try {
      // Preparar datos para el backend
      const userData = {
        rol: formData.cargo,
        tipo_documento: formData.tipoDocumento,
        documento: formData.documentoID,
        password: formData.password,
        nombre: formData.usuario
      };

      const response = await authService.register(userData);
      setSuccess("Usuario registrado con éxito");
      
      // Limpiar formulario
      setFormData({
        usuario: "",
        cargo: "",
        tipoDocumento: "",
        documentoID: "",
        password: "",
        repeatPassword: "",
      });

      // Volver al login después de 2 segundos
      setTimeout(() => {
        cambiarPagina();
      }, 2000);

    } catch (error) {
      setError(error.message);
      console.error('Error en registro:', error);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="registro-page-container">
      <div className="registro-compact-container">
        <div className="registro-form-section">
          <h2 className="registro-title">Registro</h2>
          <form onSubmit={handleSubmit} className="registro-form">
            {error && (
              <div className="error-message" style={{ 
                color: 'red', 
                marginBottom: '10px', 
                fontSize: '14px',
                textAlign: 'center'
              }}>
                {error}
              </div>
            )}
            {success && (
              <div className="success-message" style={{ 
                color: 'green', 
                marginBottom: '10px', 
                fontSize: '14px',
                textAlign: 'center'
              }}>
                {success}
              </div>
            )}
            <div className="form-group">
              <input
                type="text"
                name="usuario"
                value={formData.usuario}
                onChange={handleChange}
                className="registro-input"
                placeholder="Usuario"
                required
              />
            </div>

            <div className="form-group">
              <select
                name="cargo"
                value={formData.cargo}
                onChange={handleChange}
                className="registro-input"
                required
                style={{ color: "#a6b2a0" }}
              >
                <option value="" disabled>
                  Cargo
                </option>
                <option value="administrador">Instructor</option>
                <option value="inspector">Inspector</option>
                <option value="aprendiz">Aprendiz</option>
              </select>
            </div>

            <div className="form-group">
              <select
                name="tipoDocumento"
                value={formData.tipoDocumento}
                onChange={handleChange}
                className="registro-input"
                required
                style={{ color: "#a6b2a0" }}
              >
                <option value="" disabled>
                  Tipo de Documento
                </option>
                <option value="tarjetaid">Tarjeta de Identidad</option>
                <option value="cedula">Cédula Ciudadana</option>
                <option value="extranjera">Cédula Extranjera</option>
              </select>
            </div>

            <div className="form-group">
              <input
                type="text"
                name="documentoID"
                value={formData.documentoID}
                onChange={handleChange}
                className="registro-input"
                placeholder="Documento ID"
                required
              />
            </div>

            <div className="form-group">
              <input
                type="password"
                name="password"
                value={formData.password}
                onChange={handleChange}
                className="registro-input"
                placeholder="Contraseña"
                required
              />
            </div>

            <div className="form-group">
              <input
                type="password"
                name="repeatPassword"
                value={formData.repeatPassword}
                onChange={handleChange}
                className="registro-input"
                placeholder="Repetir Contraseña"
                required
              />
            </div>

            <button 
              type="submit" 
              className="registro-button"
              disabled={loading}
            >
              {loading ? 'Registrando...' : 'Registrar'}
              <img src={registrar} />
            </button>
          </form>
          <p className="login-register-text">
            ¿Ya tienes cuenta?{" "}
            <button
              type="button"
              onClick={cambiarPagina}
              className="login-register-link"
            >
              Inicia sesión aquí
            </button>
          </p>
        </div>
        <div className="registro-image-section">
          <img
            src={fondoLogin}
            alt="Fondo registro"
            className="registro-image"
          />
        </div>
      </div>
    </div>
  );
};

export default Register;
