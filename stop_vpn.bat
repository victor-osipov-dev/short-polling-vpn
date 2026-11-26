@echo off
setlocal
REM There is no sidecar DoH forwarder any more: DNS-over-HTTPS is built
REM into the client. Stop the VPN cleanly from the client's system-tray
REM menu (right-click the icon -> Exit). A clean exit removes the TUN
REM routes; force-killing the process can leave them behind.

set "IMAGE=Short-Polling-VPN-1.1.0.exe"

REM /FO CSV keeps the full image name (the table view truncates it).
tasklist /FI "IMAGENAME eq %IMAGE%" /FO CSV /NH 2>nul | find /I "%IMAGE%" >nul
if errorlevel 1 (
    echo [SPVPN] Client is not running.
    exit /b 0
)

if /I "%~1"=="--force" goto force

echo [SPVPN] Client is running.
echo [SPVPN] Right-click the tray icon and choose Exit to stop it cleanly.
echo [SPVPN] Use "%~nx0 --force" only if the app is frozen.
exit /b 0

:force
echo [SPVPN] Force-stopping %IMAGE% ...
taskkill /IM "%IMAGE%" /F >nul 2>&1
ping -n 3 127.0.0.1 >nul
tasklist /FI "IMAGENAME eq %IMAGE%" /FO CSV /NH 2>nul | find /I "%IMAGE%" >nul
if not errorlevel 1 (
    echo [SPVPN] Could not stop the client. If it is elevated, run this script as Administrator.
    exit /b 1
)
echo [SPVPN] Client force-stopped.
echo [SPVPN] If networking is broken afterwards, reconnect the SPVPN adapter or reboot.
exit /b 0