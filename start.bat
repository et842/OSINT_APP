@echo off
REM OSINT Dashboard launcher - opens backend and frontend in separate windows
start "OSINT Backend"  cmd /k "cd /d %~dp0backend && ..\venv\Scripts\python.exe app.py"
start "OSINT Frontend" cmd /k "cd /d %~dp0frontend && npm start"
