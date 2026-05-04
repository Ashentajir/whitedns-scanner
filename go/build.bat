@echo off
REM Build Windows executable with PyInstaller
REM Uses the virtual environment in .venv

echo [*] Activating virtual environment and installing build dependencies...
call .venv\Scripts\activate.bat
pip install -q -r requirements-build.txt

echo [*] Building Windows executable (scanner_py.exe)...
pyinstaller --noconfirm --onefile --spec scanner_py.exe.spec

echo [*] Moving executable to repository root...
if exist dist\scanner_py.exe (
    move /Y dist\scanner_py.exe .\scanner_py.exe
    echo [+] Successfully built scanner_py.exe
) else (
    echo [-] Build failed - executable not found in dist folder
    exit /b 1
)

echo.
echo Build complete. Executable: scanner_py.exe
pause
