@echo off
setlocal
title Falcon Local Engine Setup
cd /d "%~dp0"
echo ==========================================
echo   FALCON LOCAL ENGINE - WINDOWS SETUP
echo ==========================================
echo.
where python >nul 2>nul || (echo [ERROR] Python was not found.& pause & exit /b 1)
echo [OK] Python found.
set "TSK="
for %%P in (
"C:\Falcon\sleuthkit\bin"
"C:\Falcon\sleuthkit"
"C:\Program Files\sleuthkit\bin"
"C:\Program Files\Sleuth Kit\bin"
"%~dp0tools\sleuthkit\bin"
"%~dp0tools\sleuthkit"
) do if exist "%%~P\fls.exe" if exist "%%~P\mactime.exe" set "TSK=%%~P"
if not defined TSK (
 echo.
 echo [NEEDED] Sleuth Kit Windows Binaries were not found.
 echo Download the official Windows Binaries from:
 echo https://sleuthkit.org/sleuthkit/download.php
 echo.
 echo Extract them so fls.exe is under:
 echo C:\Falcon\sleuthkit\bin
 echo.
 start "" "https://sleuthkit.org/sleuthkit/download.php"
 pause
 exit /b 2
)
echo [OK] Sleuth Kit: %TSK%
set "PATH=%TSK%;%PATH%"
echo.
echo Starting Falcon Local Engine...
python falcon_local.py
pause
