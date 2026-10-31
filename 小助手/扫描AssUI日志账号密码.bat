@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

echo ============================================================
echo   AssUI_Elec Log Credential Scanner by 因式分解x
echo ============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0AssUI_CredScan.ps1" %*

echo.
pause