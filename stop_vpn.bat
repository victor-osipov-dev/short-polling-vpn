@echo off
REM Stop DNS-over-HTTPS forwarder

echo [SPVPN] Stopping DoH DNS forwarder...
for /f "tokens=2" %%p in ('tasklist /fi "WINDOWTITLE eq doh-forwarder" /nh 2^>nul') do (
    taskkill /pid %%p /f >nul 2>&1
)
echo [SPVPN] DoH forwarder stopped (if it was running).
echo [SPVPN] Close the VPN client window manually.