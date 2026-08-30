@echo off
cd /d "%~dp0"
start "" pythonw vpn_gui.py --config config.yaml
