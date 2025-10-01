import React, { useState } from "react";
import ModalBase from "../ModalBase";
import "../modals.css";

const ModalEntradas = ({ isOpen, onClose, onGuardar }) => {
  const [formData, setFormData] = useState({
    producto: "",
    cantidad: "",
    proveedor: "",
    fechaVencimiento: "",
    observaciones: "",
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
    <ModalBase isOpen={isOpen} onClose={onClose} title="Registrar Entrada">
      <div className="form-row">
        <label>Producto:</label>
        <input
          type="text"
          name="producto"
          value={formData.producto}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Cantidad:</label>
        <input
          type="number"
          name="cantidad"
          value={formData.cantidad}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Proveedor:</label>
        <input
          type="text"
          name="proveedor"
          value={formData.proveedor}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Fecha de Vencimiento:</label>
        <input
          type="date"
          name="fechaVencimiento"
          value={formData.fechaVencimiento}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Observaciones:</label>
        <textarea
          name="observaciones"
          value={formData.observaciones}
          onChange={handleChange}
        />
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

export default ModalEntradas;
