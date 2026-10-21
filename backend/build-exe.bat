@echo off
REM Build bundled backend exe -> extension/server/ (A1 packaging)
cd /d "%~dp0"
where uvicorn >nul 2>&1 || (echo Install backend venv first & exit /b 1)
python -m pip install -q pyinstaller
rmdir /s /q dist build 2>nul
pyinstaller codeshield-backend.spec --noconfirm
if not exist "dist\codeshield-backend.exe" (echo BUILD FAILED & exit /b 1)
mkdir "..\extension\server" 2>nul
copy /y "dist\codeshield-backend.exe" "..\extension\server\codeshield-backend.exe"
echo OK: ..\extension\server\codeshield-backend.exe
