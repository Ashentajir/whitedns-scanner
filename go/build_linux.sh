#!/bin/bash
# Build Linux executable with PyInstaller
# Usage: bash build_linux.sh

set -e

echo "[*] Creating Python virtual environment..."
python3 -m venv .venv_linux || true

echo "[*] Activating virtual environment..."
source .venv_linux/bin/activate

echo "[*] Installing build dependencies..."
pip install -q -r requirements-build.txt

echo "[*] Building Linux executable (scanner_py)..."
pyinstaller --noconfirm \
    --onefile \
    --name scanner_py \
    --hidden-import=dns.message \
    --hidden-import=dns.query \
    --hidden-import=dns.exception \
    --collect-submodules dns \
    --collect-all aiohttp \
    --collect-all rich \
    --collect-all questionary \
    cloudflareCdnScanner.py

echo "[*] Moving executable to repository root..."
if [ -f dist/scanner_py ]; then
    mv dist/scanner_py ./scanner_py_linux
    chmod +x ./scanner_py_linux
    echo "[+] Successfully built scanner_py_linux"
else
    echo "[-] Build failed - executable not found in dist folder"
    exit 1
fi

echo ""
echo "Build complete. Executable: scanner_py_linux"
echo "To run: ./scanner_py_linux"
