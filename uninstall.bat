@echo off
chcp 65001 >nul
setlocal
title RDPGuard - Uninstall

set "ESC="
set "GRN=%ESC%[92m"
set "YEL=%ESC%[93m"
set "RED=%ESC%[91m"
set "RST=%ESC%[0m"

rem Relaunch with admin rights if needed
net session >nul 2>&1
if errorlevel 1 (
    echo %YEL%[*]%RST% Requesting administrator privileges...
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"

if exist "dist\rdpguard.exe" (
    set "RDPGUARD_CMD=dist\rdpguard.exe"
) else (
    set "RDPGUARD_CMD=python run.py"
)

echo %YEL%[*]%RST% Stopping and removing service...
%RDPGUARD_CMD% remove
if errorlevel 1 (
    echo %RED%[x]%RST% Failed to remove service.
    pause
    exit /b 1
)

echo %GRN%[+]%RST% Done. ข้อมูล config/ฐานข้อมูลอยู่ข้าง exe (หรือ %ProgramData%\RDPGuard ในโหมด source)
echo     ลบไฟล์ config.ini / rdpguard.db ทิ้งเองถ้าต้องการล้างทั้งหมด
pause
