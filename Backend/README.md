# Backend (FastAPI) - Sistema de Gestión de Inventario

## Configuración
1. Copia `.env.example` a `.env` y ajusta valores.
2. Crea la BD ejecutando `db/schema.sql` en MySQL.

## Ejecutar
```bash
cd backend
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload --port 4000
```

## Endpoints Implementados

### Autenticación
- `POST /api/auth/login` - Inicio de sesión
- `POST /api/auth/register` - Registro de usuarios

### Productos
- `GET /api/productos/` - Listar todos los productos
- `POST /api/productos/` - Crear producto
- `GET /api/productos/{id}` - Obtener producto específico
- `PUT /api/productos/{id}` - Actualizar producto
- `DELETE /api/productos/{id}` - Eliminar producto
- `GET /api/productos/materiales-formacion` - Listar materiales de formación
- `GET /api/productos/estado-stock` - Estado de stock con semáforo visual
- `GET /api/productos/reporte-inventario` - Reporte general de inventario

### Lotes
- `GET /api/lotes/` - Listar todos los lotes
- `POST /api/lotes/` - Crear lote
- `GET /api/lotes/{id}` - Obtener lote específico
- `PUT /api/lotes/{id}` - Actualizar lote
- `DELETE /api/lotes/{id}` - Eliminar lote
- `GET /api/lotes/con-productos` - Lotes con información de productos
- `GET /api/lotes/proximos-vencer` - Lotes próximos a vencer
- `GET /api/lotes/vencidos` - Lotes vencidos
- `POST /api/lotes/actualizar-estados` - Actualizar estados automáticamente

### Alertas
- `GET /api/alertas/` - Listar alertas
- `POST /api/alertas/` - Crear alerta
- `PUT /api/alertas/{id}` - Actualizar alerta
- `GET /api/alertas/con-detalles` - Alertas con detalles
- `GET /api/alertas/pendientes` - Alertas pendientes
- `PUT /api/alertas/{id}/marcar-atendida` - Marcar alerta como atendida

### Movimientos
- `GET /api/movimientos/` - Listar movimientos
- `POST /api/movimientos/` - Crear movimiento
- `GET /api/movimientos/con-detalles` - Movimientos con detalles
- `GET /api/movimientos/por-usuario/{id}` - Movimientos por usuario
- `GET /api/movimientos/por-tipo/{tipo}` - Movimientos por tipo

## Funcionalidades Implementadas

### ✅ Gestión de Inventarios por Lotes
- Fecha de ingreso
- Fecha de vencimiento
- Cantidad disponible
- Estado automático (vigente, próximo a vencer, vencido)

### ✅ Alertas y Notificaciones
- Alertas por bajo nivel de stock
- Alertas por productos próximos a vencer
- Semáforo visual (verde/amarillo/rojo)

### ✅ Materiales de Formación
- Campo `es_material_formacion` en productos
- Endpoint específico para materiales de formación

### ✅ Reportes
- Reporte general de inventario con información por lote
- Estado de stock con colores
- Lotes próximos a vencer
- Lotes vencidos

### ✅ Validaciones Automáticas
- Actualización automática de stock al crear/actualizar lotes
- Cálculo automático de estados basado en fechas de vencimiento
- Validación de existencia de productos

### ✅ Triggers de Base de Datos
- Actualización automática de stock
- Cálculo automático de estados de lotes

## Usuarios de Prueba
- Instructor: `1001234567` / `instructor123`
- Aprendiz: `1056789123` / `aprendiz1234`
- Inspector: `1056789478` / `inspector12`

## Notas Importantes
- El sistema actualiza automáticamente las contraseñas en texto plano a bcrypt en el primer login
- Los triggers de MySQL mantienen el stock actualizado automáticamente
- Los estados de lotes se calculan automáticamente basado en fechas de vencimiento
