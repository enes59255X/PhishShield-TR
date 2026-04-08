@echo off
title PhishShield TR - Sunucu
color 0A

echo PhishShield TR - Otomatik Sunucu Baslatiliyor...
echo ==================================================
echo.

echo 1. Gerekli paketler kontrol ediliyor...
py -m pip install fastapi uvicorn requests dnspython python-whois python-multipart python-dotenv jinja2 aiosqlite httpx tldextract --quiet

echo.
echo 2. Sunucu baslatiliyor...
echo    API: http://127.0.0.1:8002
echo    Durum: PhishShield TR v2.0
echo.
echo ==================================================
echo Sunucu calisiyor... (Ctrl+C ile durdur)
echo ==================================================

py app.py

pause
