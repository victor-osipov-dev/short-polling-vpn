@echo off
cd /d "%~dp0"

where pyinstaller >nul 2>&1
if %errorlevel% neq 0 (
    echo Installing PyInstaller...
    pip install pyinstaller
)

echo Building VPN Client...
pyinstaller --noconfirm --onefile --windowed ^
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
    --collect-all httpx ^
    --collect-all httpcore ^
    vpn_gui.py

echo.
if exist "dist\VPN Client.exe" (
    echo Done! Exe: dist\VPN Client.exe
) else (
    echo Build failed. Check errors above.
)
pause
