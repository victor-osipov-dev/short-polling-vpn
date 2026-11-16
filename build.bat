@echo off
setlocal
cd /d "%~dp0"

rem --- Выбираем Python: локальный .venv, иначе системный ---
set "PY=python"
set "PYI=pyinstaller"
if exist ".venv\Scripts\python.exe" (
    set "PY=.venv\Scripts\python.exe"
    set "PYI=.venv\Scripts\pyinstaller.exe"
)

"%PY%" -c "import PyInstaller" >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller into the local environment...
    "%PY%" -m pip install --upgrade pyinstaller
)
if not exist "%PYI%" (
    set "PYI=%PY% -m PyInstaller"
)

echo Building VPN Client...
%PYI% --noconfirm --onefile --windowed ^
    --name "VPN Client" ^
    --hidden-import yaml ^
    --hidden-import httpx ^
    --hidden-import httpcore ^
    --hidden-import h2 ^
    --hidden-import cryptography ^
    --hidden-import aiohttp ^
    --hidden-import tunnel ^
    --hidden-import cdn_paths ^
    --hidden-import socks5_server ^
    --hidden-import protocol ^
    --hidden-import crypto_utils ^
    --hidden-import subscription ^
    --hidden-import split_routing ^
    --hidden-import desktop_client ^
    --hidden-import desktop_config ^
    --hidden-import connection_test ^
    --hidden-import tun_mode ^
    --hidden-import vpn_helper ^
    --hidden-import pystray ^
    --hidden-import PIL ^
    --hidden-import PIL.Image ^
    --hidden-import PIL.ImageDraw ^
    --add-binary "bin\win\tun2proxy-bin.exe;bin\win" ^
    --add-binary "bin\win\wintun.dll;bin\win" ^
    --add-data "bin\win\NOTICE.md;bin\win" ^
    --collect-all httpx ^
    --collect-all httpcore ^
    --collect-all pystray ^
    vpn_gui.py

echo.
if exist "dist\VPN Client.exe" (
    echo Done! Exe: dist\VPN Client.exe
) else (
    echo Build failed. Check errors above.
)
pause
