@echo off
chcp 65001 >nul
setlocal
title RDPGuard - Build (PyInstaller)

rem วิธีอ่าน ESC จาก prompt $E (ไม่ฝัง literal 0x1B ลงไฟล์ — กัน cmd parse พัง)
for /f %%a in ('echo prompt $E ^| cmd') do set "ESC=%%a"
set "GRN=%ESC%[92m"
set "YEL=%ESC%[93m"
set "RED=%ESC%[91m"
set "CYN=%ESC%[96m"
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

rem ---- เลือกว่า: จบแค่บิว หรือ บิวแล้วติดตั้ง service ----
rem ใช้กับ argument ได้: build.bat build / build.bat install (ไม่ถาม)
set "MODE=%~1"
if /i "%MODE%"=="build" goto :done
if /i "%MODE%"=="install" goto :do_install
if not "%MODE%"=="" (
    echo %RED%[x]%RST% ไม่รู้จักตัวเลือก "%MODE%" — ใช้ build หรือ install
    pause
    exit /b 1
)
echo.
echo เลือกขั้นตอนต่อไป:
echo   [1] จบแค่บิว %CYN%(ค่าเริ่มต้น)%RST%
echo   [2] บิวแล้วติดตั้ง service %CYN%(รัน install.bat — ขอ admin เอง)%RST%
set /p "CHOICE=เลือก (1 หรือ 2): "
if "%CHOICE%"=="2" goto :do_install
goto :done

:do_install
echo %YEL%[*]%RST% ติดตั้ง Windows Service...
call install.bat
goto :done

:done
echo.
echo %GRN%[+]%RST% เสร็จสิ้น — exe อยู่ที่ dist\rdpguard.exe
pause
