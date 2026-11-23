@echo off
setlocal
@title XraySubMapper
@cd /d "%~dp0"

set "PY_EXE="
set "PY_ARGS="

if exist ".venv\Scripts\python.exe" (
    set "PY_EXE=.venv\Scripts\python.exe"
    goto :RUN
)

if exist "venv\Scripts\python.exe" (
    set "PY_EXE=venv\Scripts\python.exe"
    goto :RUN
)

for /f "delims=" %%I in ('where python.exe 2^>nul') do (
    call :CHECK_PY "%%~fI" ""
    if defined PY_EXE goto :RUN
)

for /f "delims=" %%I in ('where py.exe 2^>nul') do (
    call :CHECK_PY "%%~fI" "-3"
    if defined PY_EXE goto :RUN
)

echo [ERROR] Python 3 was not found in .venv or system PATH!
pause
exit /b 1

:CHECK_PY
set "CAND=%~1"
if /i "%CAND:\WindowsApps\=%"=="%CAND%" (
    set "PY_EXE=%~1"
    set "PY_ARGS=%~2"
)
exit /b 0

:RUN
"%PY_EXE%" %PY_ARGS% main.py %*
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [ERROR] Process exited with code: %ERRORLEVEL%
    pause
)
