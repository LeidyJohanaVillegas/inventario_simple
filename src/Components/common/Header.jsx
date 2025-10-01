import "./common.css";
import { useModal } from "../Modales/Usuarios/ModalContext";
import { useSearch } from "./Context/SearchContext";

const Header = () => {
  const { openModal } = useModal();
  const { searchTerm, setSearchTerm } = useSearch();

  return (
    <header className="header">
      <input
        type="search"
        placeholder="Buscar..."
        className="search-input"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
      />
      <div className="profile" onClick={openModal}>
        <span>Admin</span>
        <div className="profile-pic"></div>
      </div>
    </header>
  );
};

export default Header;
