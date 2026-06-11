@echo off
REM ============================================================================
REM Aegis-360 AI v6.0 -- Automated Installer (Windows via WSL2)
REM ============================================================================
REM
REM Aegis-360 AI is designed for Kali Linux / Ubuntu.
REM On Windows, it runs best inside WSL2 (Windows Subsystem for Linux).
REM
REM This script will:
REM   1. Check if WSL2 is installed
REM   2. Optionally install WSL2 with Ubuntu if missing
REM   3. Run the Linux installer (install.sh) inside WSL2
REM ============================================================================

title Aegis-360 AI v6.0 Installer
color 0A

echo.
echo   ██╗  ██╗███████╗██╗  ██╗███████╗████████╗██████╗ ██╗██╗  ██╗███████╗
echo   ██║  ██║██╔════╝╚██╗██╔╝██╔════╝╚══██╔══╝██╔══██╗██║██║ ██╔╝██╔════╝
echo   ███████║█████╗   ╚███╔╝ ███████╗   ██║   ██████╔╝██║█████╔╝ █████╗
echo   ██╔══██║██╔══╝   ██╔██╗ ╚════██║   ██║   ██╔══██╗██║██╔═██╗ ██╔══╝
echo   ██║  ██║███████╗██╔╝ ██╗███████║   ██║   ██║  ██║██║██║  ██╗███████╗
echo   ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝╚═╝  ╚═╝╚══════╝
echo   Aegis-360 AI v6.0 -- Windows Installer
echo.

REM ── Check for WSL ──────────────────────────────────────────────────────────
echo [i] Checking for WSL2...
wsl --status >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [!] WSL2 not found.
    echo [i] To install WSL2, run the following in an ADMIN PowerShell:
    echo.
    echo     wsl --install -d Ubuntu-24.04
    echo     wsl --set-default-version 2
    echo.
    echo [i] After WSL2 is installed, re-run this script OR manually:
    echo     1. Open Ubuntu in WSL2
    echo     2. cd to the aegis-360-ai directory
    echo     3. Run: bash install.sh
    echo.
    pause
    exit /b 1
)

echo [+] WSL2 detected.
echo.

REM ── Get WSL path ─────────────────────────────────────────────────────────
set "WIN_PATH=%~dp0"
REM Convert Windows path to WSL path
for /f "tokens=*" %%i in ('wsl wslpath -u "%WIN_PATH%"') do set WSL_PATH=%%i

echo [i] Project path in WSL: %WSL_PATH%
echo.

REM ── Run Linux installer inside WSL ───────────────────────────────────────
echo [+] Running install.sh inside WSL2...
echo.
wsl bash "%WSL_PATH%install.sh"

if %ERRORLEVEL% equ 0 (
    echo.
    echo [+] Installation complete!
    echo.
    echo [i] To start Aegis-360 AI:
    echo     1. Open WSL2 (Ubuntu terminal)
    echo     2. cd %WSL_PATH%
    echo     3. source aegis-360-env/bin/activate
    echo     4. python3 aegis_360_server.py --port 8888
    echo.
    echo [i] To use with Claude Desktop:
    echo     - Copy aegis-360-ai-mcp.json contents into Claude Desktop config
    echo     - Config location: %%APPDATA%%\Claude\claude_desktop_config.json
    echo.
) else (
    echo.
    echo [!] Installation encountered errors. Check install.log for details.
    echo.
)

echo [i] See INSTALL.md and DEPLOYMENT.md for full documentation.
echo.
pause
