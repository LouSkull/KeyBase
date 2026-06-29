@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
  set "PYTHON=.venv\Scripts\python.exe"
) else (
  set "PYTHON=python"
)

%PYTHON% -c "import fastapi, uvicorn, multipart, psycopg, pymysql" >nul 2>nul
if errorlevel 1 (
  echo Installing server dependencies...
  %PYTHON% -m pip install -r requirements.txt
  if errorlevel 1 exit /b 1
)

echo Starting Key Base from config.yml
%PYTHON% -m keybase
