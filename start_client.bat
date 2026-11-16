@echo off
cd /d "%~dp0"

rem Консольный клиент (без GUI). Требует config.yaml с mode: client.
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" main.py --config config.yaml
    exit /b %errorlevel%
)

where python >nul 2>&1
if %errorlevel% neq 0 (
    echo Python не найден. Установите Python 3.12+ или создайте .venv:
    echo   uv venv .venv
    echo   uv pip install -r requirements.txt
    pause
    exit /b 1
)

python main.py --config config.yaml
