@echo off
REM Start Barrier: API + dashboard on http://127.0.0.1:7777
setlocal
cd /d "%~dp0"

set "PY="
if exist ".venv\Scripts\python.exe"    set "PY=.venv\Scripts\python.exe"
if not defined PY if exist "..\.venv\Scripts\python.exe" set "PY=..\.venv\Scripts\python.exe"

if not defined PY (
    echo Creating virtual environment...
    py -m venv .venv || python -m venv .venv
    if errorlevel 1 (
        echo.
        echo Could not create the virtual environment.
        echo Install Python 3.10+ from https://python.org and try again.
        echo.
        pause
        exit /b 1
    )
    set "PY=.venv\Scripts\python.exe"
    "%PY%" -m pip install --quiet --upgrade pip
    "%PY%" -m pip install --quiet fastapi "uvicorn[standard]"
)

REM Make sure the deps are present even when reusing an existing venv.
"%PY%" -c "import fastapi, uvicorn" 2>nul
if errorlevel 1 (
    echo Installing dependencies...
    "%PY%" -m pip install --quiet fastapi "uvicorn[standard]"
)

if not exist "data\barrier.db" (
    echo Seeding the demo story...
    "%PY%" demo\demo.py
)

echo.
echo Barrier is starting on http://127.0.0.1:7777
echo Press Ctrl+C to stop.
echo.
start "" http://127.0.0.1:7777
"%PY%" -m barrier.api
