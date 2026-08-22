@echo off
REM Dashboard web - http://localhost:5173
cd /d "%~dp0dashboard"
title Dashboard - port 5173
echo.
echo   Dashboard  http://localhost:5173
echo.
if not exist "node_modules" (
    echo   Installation des dependances, patientez...
    call npm install --no-audit --no-fund
    echo.
)
call npm run dev
echo.
echo   Le dashboard s'est arrete.
pause
