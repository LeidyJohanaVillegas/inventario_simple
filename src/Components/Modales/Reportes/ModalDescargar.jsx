import React from "react";
import jsPDF from "jspdf";
import "jspdf-autotable";
import "./modalreportes.css";

const ModalDescargar = ({ isOpen, onClose, data = [] }) => {
  if (!isOpen) return null;

  const handleDownloadPDF = () => {
    if (!data || data.length === 0) {
      alert("No hay datos para exportar.");
      return;
    }

    const doc = new jsPDF();
    doc.text("Reporte de Historial", 14, 10);

    doc.autoTable({
      head: [["Fecha", "Acción", "Detalle", "Responsable"]],
      body: data.map((item) => [
        item.fecha,
        item.accion,
        item.detalle,
        item.responsable,
      ]),
    });

    doc.save("reporte_historial.pdf");
  };

  const handleDownloadCSV = () => {
    if (!data || data.length === 0) {
      alert("No hay datos para exportar.");
      return;
    }

    const headers = ["Fecha", "Acción", "Detalle", "Responsable"];
    const rows = data.map((item) => [
      item.fecha,
      item.accion,
      item.detalle,
      item.responsable,
    ]);

    // Convertir a CSV
    let csvContent =
      headers.join(",") +
      "\n" +
      rows.map((row) => row.map((val) => `"${val}"`).join(",")).join("\n");

    // Crear y descargar archivo
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.setAttribute("download", "reporte_historial.csv");
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="descargar-overlay">
      <div className="descargar-container">

        <div className="descargar-header">
          <h2>Descargar Reporte</h2>
          <button className="descargar-close" onClick={onClose}>
            ×
          </button>
        </div>

        <div className="descargar-body">
          <p>Elige el formato en el que deseas descargar el reporte:</p>
          <div className="descargar-options">
            <button className="btn-formato" onClick={handleDownloadPDF}>
              📄 PDF
            </button>
            <button className="btn-formato" onClick={handleDownloadCSV}>
              📊 CSV
            </button>
          </div>
        </div>

        {/* Footer */}
        <div className="descargar-footer">
          <button className="btn-cerrar" onClick={onClose}>
            Cancelar
          </button>
        </div>
      </div>
    </div>
  );
};

export default ModalDescargar;
