@echo off
REM Start DNS-over-HTTPS forwarder + Short-Polling VPN
REM This ensures DNS resolution works even when plain UDP DNS is blocked

echo [SPVPN] Starting DoH DNS forwarder on port 5533...
start "doh-forwarder" /B /MIN "%ProgramFiles%\nodejs\node.exe" "C:\Users\victor\Desktop\Projects\vpn\short-polling-vpn\doh-forwarder.js"
echo [SPVPN] Waiting 2 seconds for forwarder to start...
timeout /t 2 /nobreak >nul

echo [SPVPN] Starting Short-Polling VPN client...
start "" "C:\Users\victor\Desktop\Short-Polling-VPN-1.0.1.exe"

echo [SPVPN] VPN client started. DoH forwarder is running on port 5533.
echo [SPVPN] To stop: run stop_vpn.bat