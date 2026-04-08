@echo off
title PhishShield TR - Sunucu
color 0A

echo PhishShield TR - Otomatik Sunucu Baslatiliyor...
echo ==================================================
echo.

echo 1. Port 8002 temizleniyor...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8002 ^| findstr LISTENING') do (
    echo    Process %%a sonlandiriliyor...
    taskkill /F /PID %%a >nul 2>&1
)
timeout /t 2 /nobreak >nul

echo.
echo 2. Sunucu baslatiliyor...
echo    API: http://127.0.0.1:8002
echo    Dashboard: http://127.0.0.1:8002
echo    Durum: PhishShield TR v2.0
echo.
echo ==================================================
echo Sunucu calisiyor... (Ctrl+C ile durdur)
echo ==================================================

cd backend
py simple_server.py

pause
