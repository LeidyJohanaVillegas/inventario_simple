import mysql.connector
from mysql.connector import Error
import os
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

# Configuración de la base de datos
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'localhost'),
    'port': int(os.getenv('DB_PORT', 3306)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', ''),
    'database': os.getenv('DB_NAME', 'inventario_db'),
    'charset': 'utf8mb4',
    'autocommit': True
}

def get_database_connection():
    """Obtener conexión a la base de datos"""
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"Error al conectar a MySQL: {e}")
        return None

@contextmanager
def get_db_connection():
    """Context manager para manejar conexiones a la base de datos"""
    connection = None
    try:
        connection = get_database_connection()
        if connection:
            yield connection
        else:
            raise HTTPException(status_code=500, detail="No se pudo conectar a la base de datos")
    except Error as e:
        if connection:
            connection.rollback()
        raise HTTPException(status_code=500, detail=f"Error de base de datos: {str(e)}")
    finally:
        if connection and connection.is_connected():
            connection.close()

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """Ejecutar consulta SQL"""
    with get_db_connection() as connection:
        cursor = connection.cursor(dictionary=True)
        try:
            cursor.execute(query, params)
            
            if fetch_one:
                return cursor.fetchone()
            elif fetch_all:
                return cursor.fetchall()
            else:
                connection.commit()
                return cursor.lastrowid
        except Error as e:
            connection.rollback()
            raise HTTPException(status_code=500, detail=f"Error en consulta: {str(e)}")
        finally:
            cursor.close()

def init_database():
    """Inicializar la base de datos con las tablas necesarias"""
    try:
        connection = get_database_connection()
        if connection:
            cursor = connection.cursor()
            
            # Crear base de datos si no existe
            cursor.execute(f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']}")
            cursor.execute(f"USE {DB_CONFIG['database']}")
            
            # Crear tabla de usuarios
            cursor.execute("""
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
                )
            """)
            
            # Crear tabla de productos
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS productos (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    codigo VARCHAR(50) UNIQUE NOT NULL,
                    nombre VARCHAR(200) NOT NULL,
                    descripcion TEXT,
                    categoria VARCHAR(100),
                    unidad_medida VARCHAR(20) DEFAULT 'unidad',
                    stock_minimo INT DEFAULT 0,
                    es_material_formacion BOOLEAN DEFAULT FALSE,
                    activo BOOLEAN DEFAULT TRUE,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            """)
            
            # Crear tabla de lotes
            cursor.execute("""
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
                )
            """)
            
            # Crear tabla de movimientos
            cursor.execute("""
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
                )
            """)
            
            # Crear tabla de alertas
            cursor.execute("""
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
                )
            """)
            
            # Crear triggers para actualizar stock automáticamente
            cursor.execute("""
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
                END
            """)
            
            cursor.execute("""
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
                END
            """)
            
            connection.commit()
            cursor.close()
            connection.close()
            print("Base de datos inicializada correctamente")
            return True
    except Error as e:
        print(f"Error al inicializar la base de datos: {e}")
        return False
