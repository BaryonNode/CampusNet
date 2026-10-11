@echo off
rem CampusNet 一键启动：没有配置会弹图形向导，已配置则静默认证。
cd /d "%~dp0"

where pythonw.exe >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw.exe "connect.py" %*
    exit /b 0
)

where python.exe >nul 2>nul
if %errorlevel%==0 (
    python.exe "connect.py" %*
    if errorlevel 1 pause
    exit /b %errorlevel%
)

echo 没有找到 Python。请先安装 Python 3.9 或更高版本（勾选 Add to PATH）。
pause
exit /b 1
