@echo off
cd /d "%~dp0"

rem Локальное окружение (создано через uv: .venv) имеет приоритет —
в нём есть tkinter и все зависимости.
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" vpn_gui.py --config config.yaml
    exit /b 0
)

where pythonw >nul 2>&1
if %errorlevel% neq 0 (
    echo Python не найден. Установите Python 3.12+ или создайте .venv:
    echo   uv venv .venv
    echo   uv pip install -r requirements.txt
    pause
    exit /b 1
)

start "" pythonw vpn_gui.py --config config.yaml
