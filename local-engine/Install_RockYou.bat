@echo off
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py install_rockyou.py
) else (
  python install_rockyou.py
)
echo.
pause
