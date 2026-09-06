@echo off
title PhishShield TR API Server
color 0A
echo.
echo  ================================================
echo   PhishShield TR API v2.0 Baslatiliyor...
echo  ================================================
echo.
cd /d "%~dp0backend"
echo Backend dizinine girildi: %cd%
echo.
echo Server: http://127.0.0.1:8004
echo API Docs: http://127.0.0.1:8004/docs
echo.
echo Kapatmak için CTRL+C veya bu pencereyi kapat
echo.
python app.py
pause
