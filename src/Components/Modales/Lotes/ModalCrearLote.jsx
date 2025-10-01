// ModalCrearLote.jsx
import React, { useState } from "react";
import ModalBase from "../ModalBase";
import "../modals.css"; // Asegúrate de importar correctamente

const ModalCrearLote = ({ isOpen, onClose, onGuardar }) => {
  const [formData, setFormData] = useState({
    nombreLote: "",
    responsable: "",
    ordenes: "",
    insumos: "",
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
    <ModalBase isOpen={isOpen} onClose={onClose} title="Crear Lote">
      <div className="form-row">
        <label>Nombre del Lote:</label>
        <input
          type="text"
          name="nombreLote"
          value={formData.nombreLote}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Responsable:</label>
        <input
          type="text"
          name="responsable"
          value={formData.responsable}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Órdenes Asociadas:</label>
        <input
          type="text"
          name="ordenes"
          value={formData.ordenes}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Insumos Asignados:</label>
        <input
          type="text"
          name="insumos"
          value={formData.insumos}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Estado Inicial:</label>
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

export default ModalCrearLote;


