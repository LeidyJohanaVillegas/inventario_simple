import sqlite3
import os
from contextlib import contextmanager
from fastapi import HTTPException

# SQLite database file
DATABASE_FILE = "inventario.db"

def get_database_connection():
    """Get SQLite database connection"""
    try:
        connection = sqlite3.connect(DATABASE_FILE)
        connection.row_factory = sqlite3.Row  # To get dict-like results
        return connection
    except Exception as e:
        print(f"Error connecting to SQLite: {e}")
        return None

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    connection = None
    try:
        connection = get_database_connection()
        if connection:
            yield connection
        else:
            raise HTTPException(status_code=500, detail="Could not connect to database")
    except Exception as e:
        if connection:
            connection.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")
    finally:
        if connection:
            connection.close()

def execute_query(query, params=None, fetch_one=False, fetch_all=False):
    """Execute SQL query"""
    with get_db_connection() as connection:
        cursor = connection.cursor()
        try:
            cursor.execute(query, params or [])
            
            if fetch_one:
                row = cursor.fetchone()
                return dict(row) if row else None
            elif fetch_all:
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            else:
                connection.commit()
                return cursor.lastrowid
        except Exception as e:
            connection.rollback()
            raise HTTPException(status_code=500, detail=f"Query error: {str(e)}")
        finally:
            cursor.close()

def init_database():
    """Initialize SQLite database with necessary tables"""
    try:
        connection = get_database_connection()
        if connection:
            cursor = connection.cursor()
            
            # Create users table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    documento VARCHAR(20) UNIQUE NOT NULL,
                    nombre VARCHAR(100) NOT NULL,
                    email VARCHAR(100) UNIQUE,
                    password_hash VARCHAR(255) NOT NULL,
                    rol VARCHAR(20) NOT NULL CHECK(rol IN ('instructor', 'aprendiz', 'inspector')),
                    activo BOOLEAN DEFAULT 1,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create products table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS productos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    codigo VARCHAR(50) UNIQUE NOT NULL,
                    nombre VARCHAR(200) NOT NULL,
                    descripcion TEXT,
                    categoria VARCHAR(100),
                    unidad_medida VARCHAR(20) DEFAULT 'unidad',
                    stock_minimo INTEGER DEFAULT 0,
                    stock_actual INTEGER DEFAULT 0,
                    es_material_formacion BOOLEAN DEFAULT 0,
                    activo BOOLEAN DEFAULT 1,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create batches table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS lotes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    producto_id INTEGER NOT NULL,
                    numero_lote VARCHAR(50) NOT NULL,
                    fecha_ingreso DATE NOT NULL,
                    fecha_vencimiento DATE,
                    cantidad_inicial INTEGER NOT NULL,
                    cantidad_disponible INTEGER NOT NULL,
                    estado VARCHAR(20) DEFAULT 'vigente' CHECK(estado IN ('vigente', 'proximo_vencer', 'vencido')),
                    precio_unitario DECIMAL(10,2) DEFAULT 0.00,
                    proveedor VARCHAR(200),
                    observaciones TEXT,
                    activo BOOLEAN DEFAULT 1,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_actualizacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE,
                    UNIQUE(producto_id, numero_lote)
                )
            """)
            
            # Create movements table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS movimientos (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    lote_id INTEGER NOT NULL,
                    usuario_id INTEGER NOT NULL,
                    tipo VARCHAR(20) NOT NULL CHECK(tipo IN ('entrada', 'salida', 'ajuste')),
                    cantidad INTEGER NOT NULL,
                    motivo VARCHAR(200),
                    observaciones TEXT,
                    fecha_movimiento TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (lote_id) REFERENCES lotes(id) ON DELETE CASCADE,
                    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
                )
            """)
            
            # Create alerts table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alertas (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tipo VARCHAR(20) NOT NULL CHECK(tipo IN ('stock_bajo', 'proximo_vencer', 'vencido', 'otro')),
                    producto_id INTEGER,
                    lote_id INTEGER,
                    mensaje TEXT NOT NULL,
                    nivel VARCHAR(20) DEFAULT 'warning' CHECK(nivel IN ('info', 'warning', 'error')),
                    atendida BOOLEAN DEFAULT 0,
                    fecha_creacion TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    fecha_atencion TIMESTAMP NULL,
                    FOREIGN KEY (producto_id) REFERENCES productos(id) ON DELETE CASCADE,
                    FOREIGN KEY (lote_id) REFERENCES lotes(id) ON DELETE CASCADE
                )
            """)
            
            # Insert test users with hashed passwords
            cursor.execute("""
                INSERT OR IGNORE INTO usuarios (documento, nombre, email, password_hash, rol) VALUES
                ('1001234567', 'Instructor Principal', 'instructor@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'instructor'),
                ('1056789123', 'Aprendiz Ejemplo', 'aprendiz@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'aprendiz'),
                ('1056789478', 'Inspector Calidad', 'inspector@inventario.com', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/8K5K5K5', 'inspector')
            """)
            
            # Insert sample products
            cursor.execute("""
                INSERT OR IGNORE INTO productos (codigo, nombre, descripcion, categoria, unidad_medida, stock_minimo, es_material_formacion) VALUES
                ('PROD001', 'Laptop Dell Inspiron', 'Laptop para uso educativo', 'Tecnología', 'unidad', 5, 1),
                ('PROD002', 'Mouse Inalámbrico', 'Mouse óptico inalámbrico', 'Tecnología', 'unidad', 10, 1),
                ('PROD003', 'Teclado Mecánico', 'Teclado mecánico para programación', 'Tecnología', 'unidad', 8, 1),
                ('PROD004', 'Monitor 24 pulgadas', 'Monitor LED 24 pulgadas', 'Tecnología', 'unidad', 3, 1),
                ('PROD005', 'Cable HDMI', 'Cable HDMI 2 metros', 'Accesorios', 'unidad', 20, 0)
            """)
            
            # Insert sample batches
            cursor.execute("""
                INSERT OR IGNORE INTO lotes (producto_id, numero_lote, fecha_ingreso, fecha_vencimiento, cantidad_inicial, cantidad_disponible, precio_unitario, proveedor) VALUES
                (1, 'LAP001', '2024-01-15', '2025-01-15', 10, 8, 2500000.00, 'Dell Colombia'),
                (2, 'MOU001', '2024-01-20', '2025-01-20', 25, 20, 45000.00, 'Logitech'),
                (3, 'TEC001', '2024-01-25', '2025-01-25', 15, 12, 180000.00, 'Corsair'),
                (4, 'MON001', '2024-02-01', '2025-02-01', 5, 3, 800000.00, 'Samsung'),
                (5, 'CAB001', '2024-02-05', '2026-02-05', 50, 45, 15000.00, 'Genérico')
            """)
            
            # Update stock_actual for products
            cursor.execute("""
                UPDATE productos SET stock_actual = (
                    SELECT COALESCE(SUM(cantidad_disponible), 0)
                    FROM lotes 
                    WHERE producto_id = productos.id AND activo = 1
                )
            """)
            
            connection.commit()
            cursor.close()
            connection.close()
            print("SQLite database initialized successfully")
            return True
    except Exception as e:
        print(f"Error initializing database: {e}")
        return False

# Initialize database when module is imported
if not os.path.exists(DATABASE_FILE):
    print("Creating SQLite database...")
    init_database()
