from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, date
from enum import Enum

# Enums
class RolUsuario(str, Enum):
    instructor = "instructor"
    aprendiz = "aprendiz"
    inspector = "inspector"

class EstadoLote(str, Enum):
    vigente = "vigente"
    proximo_vencer = "proximo_vencer"
    vencido = "vencido"

class TipoMovimiento(str, Enum):
    entrada = "entrada"
    salida = "salida"
    ajuste = "ajuste"

class TipoAlerta(str, Enum):
    stock_bajo = "stock_bajo"
    proximo_vencer = "proximo_vencer"
    vencido = "vencido"
    otro = "otro"

class NivelAlerta(str, Enum):
    info = "info"
    warning = "warning"
    error = "error"

# Modelos de Usuario
class UsuarioBase(BaseModel):
    documento: str
    nombre: str
    email: Optional[EmailStr] = None
    rol: RolUsuario

class UsuarioCreate(UsuarioBase):
    password: str

class UsuarioUpdate(BaseModel):
    nombre: Optional[str] = None
    email: Optional[EmailStr] = None
    rol: Optional[RolUsuario] = None
    activo: Optional[bool] = None

class Usuario(UsuarioBase):
    id: int
    activo: bool
    fecha_creacion: datetime
    fecha_actualizacion: datetime

    class Config:
        from_attributes = True

class UsuarioLogin(BaseModel):
    documento: str
    password: str

class UsuarioResponse(BaseModel):
    id: int
    documento: str
    nombre: str
    email: Optional[str] = None
    rol: str
    activo: bool

# Modelos de Producto
class ProductoBase(BaseModel):
    codigo: str
    nombre: str
    descripcion: Optional[str] = None
    categoria: Optional[str] = None
    unidad_medida: str = "unidad"
    stock_minimo: int = 0
    es_material_formacion: bool = False

class ProductoCreate(ProductoBase):
    pass

class ProductoUpdate(BaseModel):
    nombre: Optional[str] = None
    descripcion: Optional[str] = None
    categoria: Optional[str] = None
    unidad_medida: Optional[str] = None
    stock_minimo: Optional[int] = None
    es_material_formacion: Optional[bool] = None
    activo: Optional[bool] = None

class Producto(ProductoBase):
    id: int
    activo: bool
    stock_actual: Optional[int] = 0
    fecha_creacion: datetime
    fecha_actualizacion: datetime

    class Config:
        from_attributes = True

# Modelos de Lote
class LoteBase(BaseModel):
    producto_id: int
    numero_lote: str
    fecha_ingreso: date
    fecha_vencimiento: Optional[date] = None
    cantidad_inicial: int
    cantidad_disponible: int
    precio_unitario: float = 0.0
    proveedor: Optional[str] = None
    observaciones: Optional[str] = None

class LoteCreate(LoteBase):
    pass

class LoteUpdate(BaseModel):
    fecha_ingreso: Optional[date] = None
    fecha_vencimiento: Optional[date] = None
    cantidad_inicial: Optional[int] = None
    cantidad_disponible: Optional[int] = None
    precio_unitario: Optional[float] = None
    proveedor: Optional[str] = None
    observaciones: Optional[str] = None
    activo: Optional[bool] = None

class Lote(LoteBase):
    id: int
    estado: EstadoLote
    activo: bool
    fecha_creacion: datetime
    fecha_actualizacion: datetime

    class Config:
        from_attributes = True

class LoteConProducto(Lote):
    producto: Producto

# Modelos de Movimiento
class MovimientoBase(BaseModel):
    lote_id: int
    tipo: TipoMovimiento
    cantidad: int
    motivo: Optional[str] = None
    observaciones: Optional[str] = None

class MovimientoCreate(MovimientoBase):
    pass

class Movimiento(MovimientoBase):
    id: int
    usuario_id: int
    fecha_movimiento: datetime

    class Config:
        from_attributes = True

class MovimientoConDetalles(Movimiento):
    lote: Lote
    usuario: UsuarioResponse

# Modelos de Alerta
class AlertaBase(BaseModel):
    tipo: TipoAlerta
    producto_id: Optional[int] = None
    lote_id: Optional[int] = None
    mensaje: str
    nivel: NivelAlerta = NivelAlerta.warning

class AlertaCreate(AlertaBase):
    pass

class AlertaUpdate(BaseModel):
    atendida: Optional[bool] = None
    fecha_atencion: Optional[datetime] = None

class Alerta(AlertaBase):
    id: int
    atendida: bool
    fecha_creacion: datetime
    fecha_atencion: Optional[datetime] = None

    class Config:
        from_attributes = True

class AlertaConDetalles(Alerta):
    producto: Optional[Producto] = None
    lote: Optional[Lote] = None

# Modelos de respuesta
class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    user: UsuarioResponse

class MessageResponse(BaseModel):
    message: str
    success: bool = True

class ErrorResponse(BaseModel):
    detail: str
    success: bool = False

# Modelos para reportes
class EstadoStock(BaseModel):
    producto_id: int
    producto_nombre: str
    stock_actual: int
    stock_minimo: int
    estado: str  # 'normal', 'bajo', 'critico'
    color: str   # 'verde', 'amarillo', 'rojo'

class ReporteInventario(BaseModel):
    total_productos: int
    productos_con_stock: int
    productos_sin_stock: int
    productos_bajo_minimo: int
    total_lotes: int
    lotes_vigentes: int
    lotes_proximos_vencer: int
    lotes_vencidos: int
    valor_total_inventario: float
