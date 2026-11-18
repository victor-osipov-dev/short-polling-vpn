@echo off
setlocal
cd /d "%~dp0.."
python -m PyInstaller --onefile --clean --noconfirm ^
  --name vpn-backend ^
  --distpath backend ^
  --workpath .pybuild ^
  --specpath .pybuild ^
  --paths .. ^
  --hidden-import=yaml --hidden-import=httpx --hidden-import=winreg ^
  backend\vpn_backend.py
endlocal
