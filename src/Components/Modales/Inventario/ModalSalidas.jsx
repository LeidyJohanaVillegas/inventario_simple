import React, { useState } from "react";
import ModalBase from "../ModalBase"; 
import "../modals.css";

const ModalSalidas = ({ isOpen, onClose, onGuardar }) => {
  const [formData, setFormData] = useState({
    producto: "",
    cantidad: "",
    motivo: "",
    responsable: "",
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
    <ModalBase isOpen={isOpen} onClose={onClose} title="Registrar Salida">
      <div className="form-row">
        <label>Producto:</label>
        <input type="text" name="producto" value={formData.producto} onChange={handleChange} />
      </div>

      <div className="form-row">
        <label>Cantidad:</label>
        <input type="number" name="cantidad" value={formData.cantidad} onChange={handleChange} />
      </div>

      <div className="form-row">
        <label>Motivo:</label>
        <input type="text" name="motivo" value={formData.motivo} onChange={handleChange} />
      </div>

      <div className="form-row">
        <label>Responsable:</label>
        <input type="text" name="responsable" value={formData.responsable} onChange={handleChange} />
      </div>

      <div className="modal-footer">
        <button className="btn-cancelar" onClick={onClose}>Cancelar</button>
        <button className="btn-guardar" onClick={handleGuardar}>Guardar</button>
      </div>
    </ModalBase>
  );
};

export default ModalSalidas;


