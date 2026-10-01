@echo off
setlocal
title CTF Falcon Local - Windows
cd /d "%~dp0"
echo ==========================================
echo      CTF FALCON LOCAL ENGINE v2.26.0
echo ==========================================
echo.
where python >nul 2>nul || (echo [ERROR] Python was not found.& pause & exit /b 1)
echo [OK] Python found.

set "FLS="
set "ICAT="
for %%P in (
"C:\Falcon\sleuthkit\bin"
"C:\Falcon\sleuthkit"
"C:\Program Files\sleuthkit\bin"
"C:\Program Files\Sleuth Kit\bin"
"%~dp0tools\sleuthkit\bin"
"%~dp0tools\sleuthkit"
) do (
 if not defined FLS if exist "%%~P\fls.exe" set "FLS=%%~P\fls.exe"
 if not defined ICAT if exist "%%~P\icat.exe" set "ICAT=%%~P\icat.exe"
)
if not defined FLS (
 echo [ERROR] fls.exe was not found.
 echo Expected location: C:\Falcon\sleuthkit\bin\fls.exe
 pause
 exit /b 2
)
if not defined ICAT (
 echo [ERROR] icat.exe was not found.
 echo Expected location: C:\Falcon\sleuthkit\bin\icat.exe
 pause
 exit /b 3
)
echo [OK] fls: %FLS%
echo [OK] icat: %ICAT%
echo.
echo Starting Falcon at http://127.0.0.1:8765/
start "" cmd /c "timeout /t 2 /nobreak >nul & start "" "http://127.0.0.1:8765/""
python falcon_local.py
echo.
echo Falcon stopped.
pause
