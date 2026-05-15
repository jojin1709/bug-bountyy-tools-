@echo off
REM BugHunt.ai Windows Launcher
REM Automatically runs in WSL Kali Linux

setlocal enabledelayedexpansion

if "%1"=="" (
    echo.
    echo [*] BugHunt.ai - Windows Launcher
    echo.
    echo Usage:
    echo   bughunt.bat setup                  - Install everything
    echo   bughunt.bat hunt ^<target^>         - Hunt target
    echo   bughunt.bat hunt ^<target^> ^<scope^> - Hunt with scope
    echo.
    echo Examples:
    echo   bughunt.bat setup
    echo   bughunt.bat hunt target.com
    echo   bughunt.bat hunt target.com scope.txt
    echo.
    exit /b 1
)

REM Check if WSL installed
wsl --list >nul 2>&1
if errorlevel 1 (
    echo [!] WSL not installed. Install with:
    echo     wsl --install
    echo     wsl --install -d kali-linux
    exit /b 1
)

REM Run command in WSL
set CMD=%*
wsl -d kali-linux -- bash -c "cd /mnt/c/Users/%USERNAME%/BugHunt_AI && python3 bughunt.py %CMD%"

endlocal
