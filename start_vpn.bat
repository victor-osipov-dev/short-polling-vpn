@echo off
setlocal
REM Launch the Short-Polling VPN client.
REM DNS-over-HTTPS (RFC 8484) is built into the client, so no sidecar
REM forwarder is needed. Set the DoH endpoint in the app settings, e.g.
REM "https://8.8.8.8/dns-query" (an IP literal needs no bootstrap lookup).

set "IMAGE=Short-Polling-VPN-1.1.0.exe"
set "VPN_EXE=%~dp0%IMAGE%"
if not exist "%VPN_EXE%" set "VPN_EXE=%USERPROFILE%\Desktop\%IMAGE%"

if not exist "%VPN_EXE%" (
    echo [SPVPN] Client not found.
    echo         Put %IMAGE% next to this script or on the Desktop.
    pause
    exit /b 1
)

REM /FO CSV keeps the full image name (the table view truncates it).
tasklist /FI "IMAGENAME eq %IMAGE%" /FO CSV /NH 2>nul | find /I "%IMAGE%" >nul
if not errorlevel 1 (
    echo [SPVPN] Client is already running - open it from the system tray.
    exit /b 0
)

echo [SPVPN] Starting Short-Polling VPN client...
start "" "%VPN_EXE%"

REM ping is used instead of timeout: timeout aborts when stdin is redirected.
ping -n 4 127.0.0.1 >nul
tasklist /FI "IMAGENAME eq %IMAGE%" /FO CSV /NH 2>nul | find /I "%IMAGE%" >nul
if errorlevel 1 (
    echo [SPVPN] Client did not start. See %APPDATA%\spvpn\spvpn.log
    pause
    exit /b 1
)

echo [SPVPN] Client is running in the system tray.
echo [SPVPN] Open it and press Connect - Windows will ask for Administrator rights.
exit /b 0