@echo off
REM Build scanner_py.exe from cloudflareCdnScanner.py using the local virtualenv
REM Usage: double-click or run from repo root in PowerShell/CMD.

:: Activate virtualenv (PowerShell)
powershell -NoProfile -ExecutionPolicy RemoteSigned -Command "& '.\.venv\Scripts\Activate.ps1' ; pip install -r requirements-pyinstaller.txt ; pyinstaller --noconfirm --onefile --name scanner_py.exe cloudflareCdnScanner.py ; if exist dist\scanner_py.exe move /Y dist\scanner_py.exe .\scanner_py.exe"

necho Build script finished. If successful, scanner_py.exe will be in the repository root.
pause
