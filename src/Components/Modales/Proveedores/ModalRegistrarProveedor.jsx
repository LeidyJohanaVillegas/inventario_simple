import React, { useState } from "react";
import ModalBase from "../ModalBase"; // Importamos el ModalBase

const ModalRegistrarProveedor = ({ isOpen, onClose, onGuardar }) => {
  const [formData, setFormData] = useState({
    nombre: "",
    contacto: "",
    direccion: "",
    productosOfrecidos: "",
    estado: "Activo",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleGuardar = () => {
    onGuardar(formData);
    onClose();
  };

  return (
    <ModalBase isOpen={isOpen} onClose={onClose} title="Registrar Proveedor">
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
        <label>Contacto:</label>
        <input
          type="text"
          name="contacto"
          value={formData.contacto}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Dirección:</label>
        <input
          type="text"
          name="direccion"
          value={formData.direccion}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Productos Ofrecidos:</label>
        <input
          type="text"
          name="productosOfrecidos"
          value={formData.productosOfrecidos}
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
        <button className="btn-cancelar" onClick={onClose}>Cancelar</button>
        <button className="btn-guardar" onClick={handleGuardar}>Guardar</button>
      </div>
    </ModalBase>
  );
};

export default ModalRegistrarProveedor;


