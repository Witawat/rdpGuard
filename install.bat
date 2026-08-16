@echo off
chcp 65001 >nul
setlocal
title RDPGuard - Install

set "ESC="
set "GRN=%ESC%[92m"
set "YEL=%ESC%[93m"
set "RED=%ESC%[91m"
set "CYN=%ESC%[96m"
set "RST=%ESC%[0m"

rem Relaunch with admin rights if needed
net session >nul 2>&1
if errorlevel 1 (
    echo %YEL%[*]%RST% Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

rem Use the built exe when available, otherwise fall back to Python
if exist "dist\rdpguard.exe" (
    set "RDPGUARD_CMD=dist\rdpguard.exe"
) else (
    set "RDPGUARD_CMD=python run.py"
)

if not exist "dist\rdpguard.exe" (
    echo %GRN%[1/3]%RST% Installing dependencies ^(pywin32^)...
    python -m pip install -r requirements.txt
    if errorlevel 1 (
        echo %RED%[x]%RST% pip install failed.
        pause
        exit /b 1
    )
)

echo %GRN%[2/3]%RST% Installing Windows Service...
%RDPGUARD_CMD% install
if errorlevel 1 (
    echo %RED%[x]%RST% Failed to install service.
    pause
    exit /b 1
)

echo %GRN%[3/3]%RST% Starting service...
%RDPGUARD_CMD% start

echo.
echo %GRN%[+]%RST% Done. ตรวจสอบได้ที่:
echo     %CYN%%RDPGUARD_CMD% status%RST%
echo     %CYN%%RDPGUARD_CMD% password%RST%   ^(รหัสผ่าน Web UI^)
echo     Web UI: %CYN%http://127.0.0.1:8123%RST%
pause
