@echo off
setlocal
cd /d "%~dp0.."
echo [1/3] Building backend...
call scripts\build-backend.bat
if errorlevel 1 exit /b 1
echo [2/3] Building portable app...
call npm.cmd run dist
if errorlevel 1 exit /b 1
echo [3/3] Creating desktop shortcuts...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts\create-shortcuts.ps1
echo Release ready: release\Short-Polling-VPN-1.0.0-portable.exe
endlocal
