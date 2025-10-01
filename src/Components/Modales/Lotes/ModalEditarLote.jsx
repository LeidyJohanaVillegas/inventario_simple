import React, { useState, useEffect } from "react";
import "../modals.css"; // asegúrate de que el CSS esté importado

const ModalEditarLote = ({ isOpen, onClose, onGuardar, lote }) => {
  const [formData, setFormData] = useState({
    producto: "",
    fechaIngreso: "",
    vencimiento: "",
    estado: "Activo",
  });

  // Cuando se abre el modal con un lote, cargamos los datos
  useEffect(() => {
    if (lote) {
      setFormData({
        producto: lote.producto || "",
        fechaIngreso: lote.fechaIngreso || "",
        vencimiento: lote.vencimiento || "",
        estado: lote.estado || "Activo",
      });
    }
  }, [lote]);

  if (!isOpen) return null;

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleGuardar = () => {
    onGuardar(formData);
  };

  return (
    <div className="modal-overlay">
      <div className="modal-container">
        {/* Header */}
        <div className="modal-header">
          <h2>Editar Lote</h2>
          <button className="modal-close" onClick={onClose}>
            ×
          </button>
        </div>

        {/* Body */}
        <div className="modal-body">
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
            <label>Fecha de Ingreso:</label>
            <input
              type="date"
              name="fechaIngreso"
              value={formData.fechaIngreso}
              onChange={handleChange}
            />
          </div>

          <div className="form-row">
            <label>Vencimiento:</label>
            <input
              type="date"
              name="vencimiento"
              value={formData.vencimiento}
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
        </div>

        {/* Footer */}
        <div className="modal-footer">
          <button className="btn-cancelar" onClick={onClose}>
            Cancelar
          </button>
          <button className="btn-guardar" onClick={handleGuardar}>
            Guardar
          </button>
        </div>
      </div>
    </div>
  );
};

export default ModalEditarLote;
