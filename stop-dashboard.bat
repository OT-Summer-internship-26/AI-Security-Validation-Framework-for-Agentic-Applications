@echo off
REM ============================================================
REM  Arrete l'API d'audit et le dashboard.
REM ============================================================
echo.
echo   Arret des serveurs...

REM API d'audit (uvicorn)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1
    echo     API arretee (PID %%p^)
)

REM Dashboard (Vite)
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173" ^| findstr "LISTENING"') do (
    taskkill /F /PID %%p >nul 2>&1
    echo     Dashboard arrete (PID %%p^)
)

echo.
echo   Termine.
timeout /t 2 /nobreak >nul
