@echo off
@title XraySubMapper
@cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    set "PY_CMD=.venv\Scripts\python.exe"
    goto :RUN
)

if exist "venv\Scripts\python.exe" (
    set "PY_CMD=venv\Scripts\python.exe"
    goto :RUN
)

where python >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=python"
    goto :RUN
)

where py >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    set "PY_CMD=py -3"
    goto :RUN
)

echo [ERROR] Python 3 was not found in .venv or system PATH!
pause
exit /b 1

:RUN
%PY_CMD% main.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Process exited with code: %ERRORLEVEL%
    pause
)
