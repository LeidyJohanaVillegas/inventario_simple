import { createContext, useContext, useState } from "react";
import AdminModal from "./ModalMenu";

const ModalContext = createContext();

export const ModalProvider = ({ children, cambiarPagina, setIsLoggedIn   }) => {
  const [isOpen, setIsOpen] = useState(false);

  const openModal = () => setIsOpen(true);
  const closeModal = () => setIsOpen(false);

  return (
    <ModalContext.Provider value={{ isOpen, openModal, closeModal }}>
      {children}
      <AdminModal 
      isOpen={isOpen}
      onClose={closeModal} 
      cambiarPagina={cambiarPagina} 
      setIsLoggedIn={setIsLoggedIn}
      />
    </ModalContext.Provider>
  );
};

export const useModal = () => {
  const context = useContext(ModalContext);
  if (!context) {
    throw new Error("useModal debe usarse dentro de un ModalProvider");
  }
  return context;
};
