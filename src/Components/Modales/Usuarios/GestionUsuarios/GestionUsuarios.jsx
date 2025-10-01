// GestionUsuarios.jsx
import React, { useState } from "react";
import "./gestion.css";
import ModalEditarUsuario from "../GestionUsuarios/ModalEditarUsuarios"; // Asegúrate que la ruta esté correcta

function GestionUsuarios() {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [usuarioSeleccionado, setUsuarioSeleccionado] = useState(null);

  const usuarios = [
    { id: 1, nombre: "Juan Pérez", documento: "123456789", rol: "Administrador", estado: "Activo" },
    { id: 2, nombre: "María Gómez", documento: "987654321", rol: "Usuario", estado: "Inactivo" },
    { id: 3, nombre: "Carlos Ramírez", documento: "456123789", rol: "Supervisor", estado: "Activo" },
    { id: 4, nombre: "Laura Torres", documento: "741852963", rol: "Usuario", estado: "Activo" },
    { id: 5, nombre: "Andrés López", documento: "852963741", rol: "Moderador", estado: "Inactivo" },
  ];

  const handleEditar = (usuario) => {
    setUsuarioSeleccionado(usuario);
    setIsModalOpen(true);
  };

  const handleCerrarModal = () => {
    setIsModalOpen(false);
    setUsuarioSeleccionado(null);
  };

  const handleGuardarCambios = (usuarioEditado) => {
    console.log("Usuario editado:", usuarioEditado);
    // Aquí puedes actualizar el estado global o llamar una API
  };

  return (
    <div className="gestion-usuarios">
      {/* Header */}
      <div className="gestion-header">
        <h2>GESTIÓN DE USUARIOS</h2>
      </div>

      {/* Contenido */}
      <div className="gestion-contenido">
        <div className="tabla-contenedor">
          <table>
            <thead>
              <tr>
                <th>Nombre</th>
                <th>Documento</th>
                <th>Rol</th>
                <th>Estado</th>
                <th>Acciones</th>
              </tr>
            </thead>
            <tbody>
              {usuarios.map((usuario) => (
                <tr key={usuario.id}>
                  <td>{usuario.nombre}</td>
                  <td>{usuario.documento}</td>
                  <td>{usuario.rol}</td>
                  <td>{usuario.estado}</td>
                  <td>
                    <button className="btn-editar" onClick={() => handleEditar(usuario)}>
                      Editar
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Modal de Edición */}
      <ModalEditarUsuario
        isOpen={isModalOpen}
        onClose={handleCerrarModal}
        onGuardar={handleGuardarCambios}
        usuarioSeleccionado={usuarioSeleccionado}
      />
    </div>
  );
}

export default GestionUsuarios;
