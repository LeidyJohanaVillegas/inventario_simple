// ModalEditarUsuario.jsx
import React, { useState, useEffect } from "react";
import ModalBase from "../../ModalBase";
import "../../modals.css";

const ModalEditarUsuarios = ({ isOpen, onClose, onGuardar, usuarioSeleccionado }) => {
  const [formData, setFormData] = useState({
    nombre: "",
    documento: "",
    rol: "",
    estado: "Activo",
  });

  // Cuando se abre el modal y hay un usuario seleccionado, llenar el form
  useEffect(() => {
    if (usuarioSeleccionado) {
      setFormData({
        nombre: usuarioSeleccionado.nombre || "",
        documento: usuarioSeleccionado.documento || "",
        rol: usuarioSeleccionado.rol || "",
        estado: usuarioSeleccionado.estado || "Activo",
      });
    }
  }, [usuarioSeleccionado, isOpen]);

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleGuardar = () => {
    onGuardar(formData);
    onClose();
  };

  return (
    <ModalBase isOpen={isOpen} onClose={onClose} title="Editar Usuario">
      <div className="form-row">
        <label>Nombre:</label>
        <input
          type="text"
          name="nombre"
          value={formData.nombre}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Documento:</label>
        <input
          type="text"
          name="documento"
          value={formData.documento}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Rol:</label>
        <input
          type="text"
          name="rol"
          value={formData.rol}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Estado:</label>
        <select
          name="estado"
          value={formData.estado}
          onChange={handleChange}
        >
          <option value="Activo">Activo</option>
          <option value="Inactivo">Inactivo</option>
        </select>
      </div>

      <div className="modal-footer">
        <button className="btn-cancelar" onClick={onClose}>
          Cancelar
        </button>
        <button className="btn-guardar" onClick={handleGuardar}>
          Guardar
        </button>
      </div>
    </ModalBase>
  );
};

export default ModalEditarUsuarios;

