@echo off
echo 🔧 Activando entorno virtual...
call venv\Scripts\activate.bat
echo ✅ Entorno virtual activado
echo 📦 Dependencias instaladas correctamente
echo.
echo 🚀 Para ejecutar el backend:
echo    python server.py
echo    o
echo    uvicorn app.main:app --host 127.0.0.1 --port 8082
echo.
echo 📚 Documentación API: http://127.0.0.1:8082/docs
echo.
cmd /k
