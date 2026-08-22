@echo off
REM API d'audit - http://127.0.0.1:8000
cd /d "%~dp0"
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
title API Audit - port 8000
echo.
echo   API d'audit  http://127.0.0.1:8000
echo   Documentation interactive : http://127.0.0.1:8000/docs
echo.
python -m uvicorn api.main:app --host 127.0.0.1 --port 8000
echo.
echo   L'API s'est arretee.
pause
