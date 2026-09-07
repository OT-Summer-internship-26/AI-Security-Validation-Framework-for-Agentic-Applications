@echo off
REM Dashboard web - http://localhost:5173
REM
REM  ATTENTION : ce script ne lance QUE le dashboard, pas l'API.
REM  Sans API sur 127.0.0.1:8000, le dashboard retombe sur son jeu de
REM  DEMONSTRATION - quatre audits dates de juillet 2026 - et l'historique
REM  n'affiche donc pas vos vrais audits. Un bandeau le signale desormais
REM  en tete de page, mais autant ne pas s'y mettre.
REM
REM  Pour tout demarrer :  start-dashboard.bat   (API + dashboard + navigateur)
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
