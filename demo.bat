@echo off
REM Replay the Barrier demo story against a fresh database.
REM Leave run.bat going in another window so the dashboard fills in live.
setlocal
cd /d "%~dp0"

set "PY="
if exist ".venv\Scripts\python.exe"    set "PY=.venv\Scripts\python.exe"
if not defined PY if exist "..\.venv\Scripts\python.exe" set "PY=..\.venv\Scripts\python.exe"
if not defined PY set "PY=python"

REM BARRIER_DEMO_PAUSE adds beats between scenes when presenting live.
if "%~1"=="slow" set BARRIER_DEMO_PAUSE=1.2

"%PY%" demo\demo.py %*
