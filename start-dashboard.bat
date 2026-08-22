@echo off
REM ============================================================
REM  Security Audit Console - Ooredoo Tunisie
REM  Demarre l'API d'audit + le dashboard, puis ouvre le navigateur.
REM  Double-cliquez simplement sur ce fichier.
REM ============================================================
cd /d "%~dp0"

echo.
echo   ============================================
echo     SECURITY AUDIT CONSOLE - Ooredoo Tunisie
echo     OWASP Top 10 for Agentic Applications
echo   ============================================
echo.

REM --- Liberer les ports si des serveurs tournent deja ---
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000 " ^| findstr "LISTENING"') do taskkill /F /PID %%p >nul 2>&1
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5173 " ^| findstr "LISTENING"') do taskkill /F /PID %%p >nul 2>&1

echo   [1/2] Demarrage de l'API d'audit...
start "API Audit" "%~dp0run-api.bat"

echo   [2/2] Demarrage du dashboard...
start "Dashboard" "%~dp0run-dashboard.bat"

echo.
echo   Attente du demarrage des serveurs...
timeout /t 12 /nobreak >nul

start "" http://localhost:5173

echo.
echo   ============================================
echo     Dashboard   http://localhost:5173
echo     API         http://127.0.0.1:8000
echo   ============================================
echo.
echo   Deux fenetres se sont ouvertes. Fermez-les
echo   ou lancez stop-dashboard.bat pour tout arreter.
echo.
timeout /t 5 /nobreak >nul
