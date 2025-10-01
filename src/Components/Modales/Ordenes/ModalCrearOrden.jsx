import React, { useState } from "react";
import ModalBase from "../ModalBase"; // Asegúrate de tener este componente

const ModalCrearOrden = ({ isOpen, onClose, onGuardar }) => {
  const [formData, setFormData] = useState({
    nombreLote: "",
    responsable: "",
    fechaEstimada: "",
    insumosRequeridos: "",
    estado: "Activo",
  });

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleGuardar = () => {
    onGuardar(formData);
    setFormData({
      nombreLote: "",
      responsable: "",
      fechaEstimada: "",
      insumosRequeridos: "",
      estado: "Activo",
    });
    onClose();
  };

  if (!isOpen) return null;

  return (
    <ModalBase isOpen={isOpen} onClose={onClose} title="Nueva Orden de Producción">
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
        <label>Fecha Estimada:</label>
        <input
          type="date"
          name="fechaEstimada"
          value={formData.fechaEstimada}
          onChange={handleChange}
        />
      </div>

      <div className="form-row">
        <label>Insumos Requeridos:</label>
        <input
          type="text"
          name="insumosRequeridos"
          value={formData.insumosRequeridos}
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

export default ModalCrearOrden;


