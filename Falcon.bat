@echo off
REM ==========================================================================
REM  CTF Falcon - Local Engine Launcher (Windows)
REM  يكتشف نسخة Python الفعلية ويشغّل المحرك، مع رسالة واضحة عند الفشل.
REM  Auto-detects a real Python (ignores the WindowsApps stub) and runs it.
REM  ضعه بجانب falcon_local.py، مثال:  C:\Falcon\Falcon.bat
REM ==========================================================================
setlocal enabledelayedexpansion
chcp 65001 >nul
title CTF Falcon - Local Engine

REM --- تحديد مسار المحرك ---
set "SCRIPT=%~dp0falcon_local.py"
if not exist "%SCRIPT%" set "SCRIPT=%~dp0local-engine\falcon_local.py"
if not exist "%SCRIPT%" (
    echo [Falcon] لم يُعثر على falcon_local.py بجوار هذا الملف.
    echo [Falcon] falcon_local.py was not found next to this launcher.
    pause
    goto :eof
)

set "PYEXE="

REM --- (1) مشغّل بايثون الرسمي على ويندوز: py -3 ---
where py >nul 2>nul
if not errorlevel 1 (
    for /f "delims=" %%V in ('py -3 -c "import sys;print(sys.version.split()[0])" 2^>nul') do set "PYVER=%%V"
    if defined PYVER (
        echo [Falcon] Using py -3  (Python !PYVER!)
        py -3 -u "%SCRIPT%" %*
        goto :done
    )
)

REM --- (2) مواقع التثبيت الشائعة ---
for %%D in (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python310\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
    "C:\Python313\python.exe"
    "C:\Python312\python.exe"
    "C:\Python311\python.exe"
) do (
    if exist %%~D (
        set "PYEXE=%%~D"
        goto :run
    )
)

REM --- (3) python في PATH مع تجاهل نسخة WindowsApps الوهمية ---
for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | find /i "WindowsApps" >nul
    if errorlevel 1 (
        if not defined PYEXE set "PYEXE=%%P"
    )
)
if defined PYEXE goto :run

REM --- لا يوجد Python صالح: رسالة واضحة ---
echo.
echo ============================================================
echo [Falcon] تعذّر العثور على Python صالح على هذا الجهاز.
echo          الأمر "python" هنا يشير غالبًا إلى WindowsApps ولا يعمل.
echo.
echo   الحل:
echo   1) ثبّت Python 3.10+ من: https://www.python.org/downloads/
echo      وفعّل خيار: Add python.exe to PATH
echo   2) أو شغّل المحرك يدويًا بالمسار الكامل، مثال:
echo      "%LOCALAPPDATA%\Programs\Python\Python312\python.exe" -u "%SCRIPT%"
echo.
echo [Falcon] No working Python found. The "python" command on this
echo          PC points to the WindowsApps stub. Install Python 3.10+
echo          (enable "Add to PATH"), or run the full path shown above.
echo ============================================================
echo.
pause
goto :done

:run
for /f "delims=" %%V in ('"%PYEXE%" -c "import sys;print(sys.version.split()[0])" 2^>nul') do set "PYVER=%%V"
if not defined PYVER (
    echo [Falcon] عُثر على "%PYEXE%" لكنه لا يعمل كنسخة Python صالحة.
    echo [Falcon] Found "%PYEXE%" but it is not a working Python.
    pause
    goto :done
)
echo [Falcon] Using "%PYEXE%"  (Python !PYVER!)
"%PYEXE%" -u "%SCRIPT%" %*

:done
echo.
echo [Falcon] توقّف المحرك. اضغط مفتاحًا للإغلاق.
pause >nul
endlocal
