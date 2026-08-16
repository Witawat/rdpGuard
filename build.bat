@echo off
chcp 65001 >nul
setlocal
title RDPGuard - Build (PyInstaller)

set "ESC="
set "GRN=%ESC%[92m"
set "YEL=%ESC%[93m"
set "RED=%ESC%[91m"
set "RST=%ESC%[0m"

cd /d "%~dp0"

echo %YEL%[*]%RST% Installing pyinstaller...
python -m pip install pyinstaller
if errorlevel 1 (
    echo %RED%[x]%RST% pip install pyinstaller failed.
    pause
    exit /b 1
)

echo %YEL%[*]%RST% Building exe...
python -m PyInstaller --noconfirm rdpguard.spec
if errorlevel 1 (
    echo %RED%[x]%RST% Build failed.
    pause
    exit /b 1
)

echo.
echo %GRN%[+]%RST% Build complete: dist\rdpguard.exe
echo     ต่อไปติดตั้งได้ด้วย %CYN%install.bat%RST% (จะใช้ exe อัตโนมัติ)
pause
