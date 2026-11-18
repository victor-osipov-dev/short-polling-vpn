@echo off
setlocal
cd /d "%~dp0"
set "EXE="
for /f "delims=" %%f in ('dir /b /o-n "release\Short-Polling-VPN-*-portable.exe" 2^>nul') do (
  if not defined EXE set "EXE=release\%%f"
)
if defined EXE (
  echo Starting Short Polling VPN: %EXE%
  start "" "%EXE%"
  exit /b 0
)
if exist "release\win-unpacked\Short Polling VPN.exe" (
  echo Starting unpacked Short Polling VPN
  start "" "release\win-unpacked\Short Polling VPN.exe"
  exit /b 0
)
echo Portable build not found. Run: npm run dist
pause
exit /b 1
