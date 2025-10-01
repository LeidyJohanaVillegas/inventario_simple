-- Script de creación de la base de datos para el Sistema de Gestión de Inventario
-- Ejecutar este script en MySQL para crear la estructura inicial

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS inventario_db;
USE inventario_db;

-- Crear tabla de usuarios
CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    documento VARCHAR(20) UNIQUE NOT NULL,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    rol ENUM('instructor', 'aprendiz', 'inspector') NOT NULL,
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Crear tabla de productos
CREATE TABLE IF NOT EXISTS productos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    codigo VARCHAR(50) UNIQUE NOT NULL,
    nombre VARCHAR(200) NOT NULL,
    descripcion TEXT,
    categoria VARCHAR(100),
    unidad_medida VARCHAR(20) DEFAULT 'unidad',
    stock_minimo INT DEFAULT 0,
    stock_actual INT DEFAULT 0,
    es_material_formacion BOOLEAN DEFAULT FALSE,
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Crear tabla de lotes
CREATE TABLE IF NOT EXISTS lotes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    producto_id INT NOT NULL,
    numero_lote VARCHAR(50) NOT NULL,
    fecha_ingreso DATE NOT NULL,
    fecha_vencimiento DATE,
    cantidad_inicial INT NOT NULL,
    cantidad_disponible INT NOT NULL,
    estado ENUM('vigente', 'proximo_vencer', 'vencido') DEFAULT 'vigente',
    precio_unitario DECIMAL(10,2) DEFAULT 0.00,
    proveedor VARCHAR(200),
    observaciones TEXT,
    activo BOOLEAN DEFAULT TRUE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE,
    UNIQUE KEY unique_lote (producto_id, numero_lote)
);

-- Crear tabla de movimientos
CREATE TABLE IF NOT EXISTS movimientos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    lote_id INT NOT NULL,
    usuario_id INT NOT NULL,
    tipo ENUM('entrada', 'salida', 'ajuste') NOT NULL,
    cantidad INT NOT NULL,
    motivo VARCHAR(200),
    observaciones TEXT,
    fecha_movimiento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (lote_id) REFERENCES lotes(id) ON DELETE CASCADE,
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);

-- Crear tabla de alertas
CREATE TABLE IF NOT EXISTS alertas (
    id INT AUTO_INCREMENT PRIMARY KEY,
    tipo ENUM('stock_bajo', 'proximo_vencer', 'vencido', 'otro') NOT NULL,
    producto_id INT,
    lote_id INT,
    mensaje TEXT NOT NULL,
    nivel ENUM('info', 'warning', 'error') DEFAULT 'warning',
    atendida BOOLEAN DEFAULT FALSE,
    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    fecha_atencion TIMESTAMP NULL,
    FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE,
    FOREIGN KEY (lote_id) REFERENCES lotes(id) ON DELETE CASCADE
);

-- Crear triggers para actualizar stock automáticamente
DELIMITER $$

CREATE TRIGGER IF NOT EXISTS actualizar_stock_producto
AFTER UPDATE ON lotes
FOR EACH ROW
BEGIN
    UPDATE productos 
    SET stock_actual = (
        SELECT COALESCE(SUM(cantidad_disponible), 0)
        FROM lotes 
        WHERE producto_id = NEW.producto_id AND activo = TRUE
    )
    WHERE id = NEW.producto_id;
END$$

CREATE TRIGGER IF NOT EXISTS actualizar_estado_lote
BEFORE UPDATE ON lotes
FOR EACH ROW
BEGIN
    IF NEW.fecha_vencimiento IS NOT NULL THEN
        IF NEW.fecha_vencimiento < CURDATE() THEN
            SET NEW.estado = 'vencido';
        ELSEIF NEW.fecha_vencimiento <= DATE_ADD(CURDATE(), INTERVAL 30 DAY) THEN
            SET NEW.estado = 'proximo_vencer';
        ELSE
            SET NEW.estado = 'vigente';
        END IF;
    END IF;
END$$

DELIMITER ;

-- Insertar usuarios de prueba
INSERT INTO usuarios (documento, nombre, email, password_hash, rol) VALUES
('1001234567', 'Instructor Principal', 'instructor@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'instructor'),
('1056789123', 'Aprendiz Ejemplo', 'aprendiz@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'aprendiz'),
('1056789478', 'Inspector Calidad', 'inspector@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'inspector');

-- Insertar productos de ejemplo
INSERT INTO productos (codigo, nombre, descripcion, categoria, unidad_medida, stock_minimo, es_material_formacion) VALUES
('PROD001', 'Laptop Dell Inspiron', 'Laptop para uso educativo', 'Tecnología', 'unidad', 5, TRUE),
('PROD002', 'Mouse Inalámbrico', 'Mouse óptico inalámbrico', 'Tecnología', 'unidad', 10, TRUE),
('PROD003', 'Teclado Mecánico', 'Teclado mecánico para programación', 'Tecnología', 'unidad', 8, TRUE),
('PROD004', 'Monitor 24 pulgadas', 'Monitor LED 24 pulgadas', 'Tecnología', 'unidad', 3, TRUE),
('PROD005', 'Cable HDMI', 'Cable HDMI 2 metros', 'Accesorios', 'unidad', 20, FALSE);

-- Insertar lotes de ejemplo
INSERT INTO lotes (producto_id, numero_lote, fecha_ingreso, fecha_vencimiento, cantidad_inicial, cantidad_disponible, precio_unitario, proveedor) VALUES
(1, 'LAP001', '2024-01-15', '2025-01-15', 10, 8, 2500000.00, 'Dell Colombia'),
(2, 'MOU001', '2024-01-20', '2025-01-20', 25, 20, 45000.00, 'Logitech'),
(3, 'TEC001', '2024-01-25', '2025-01-25', 15, 12, 180000.00, 'Corsair'),
(4, 'MON001', '2024-02-01', '2025-02-01', 5, 3, 800000.00, 'Samsung'),
(5, 'CAB001', '2024-02-05', '2026-02-05', 50, 45, 15000.00, 'Genérico');

-- Actualizar stock actual de productos
UPDATE productos SET stock_actual = (
    SELECT COALESCE(SUM(cantidad_disponible), 0)
    FROM lotes 
    WHERE producto_id = productos.id AND activo = TRUE
);
