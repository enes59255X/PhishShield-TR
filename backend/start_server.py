#!/usr/bin/env python3
"""
PhishShield TR - Otomatik Sunucu Starter
Tek komutla backend'i hazirlar ve baslatir.
"""

import subprocess
import sys
import os

def main():
    print("PhishShield TR - Otomatik Sunucu Baslatiliyor...")
    print("=" * 50)
    
    # Gerekli paketleri kontrol et ve kur
    required_packages = [
        'fastapi', 'uvicorn', 'requests', 'dnspython', 
        'python-whois', 'python-multipart', 'python-dotenv', 
        'jinja2', 'aiosqlite', 'httpx', 'tldextract'
    ]
    
    print("1. Gerekli paketler kontrol ediliyor...")
    try:
        for package in required_packages:
            try:
                __import__(package.replace('-', '_'))
                print(f"   {package} - OK")
            except ImportError:
                print(f"   {package} - Kuruluyor...")
                subprocess.run([sys.executable, '-m', 'pip', 'install', package], check=True)
                print(f"   {package} - Kuruldu")
    except Exception as e:
        print(f"Paket kurulum hatasi: {e}")
        return False
    
    print("\n2. Sunucu baslatiliyor...")
    print("   API: http://127.0.0.1:8002")
    print("   Durum: PhishShield TR v2.0")
    print("   Algoritma: Geliçmis sahte site tespiti")
    print("\n" + "=" * 50)
    print("Sunucu calisiyor... (Ctrl+C ile durdur)")
    print("=" * 50)
    
    # Sunucuyu baslat
    try:
        subprocess.run([sys.executable, 'app.py'], check=True)
    except KeyboardInterrupt:
        print("\nSunucu durduruldu.")
    except Exception as e:
        print(f"Sunucu hatasi: {e}")
        return False

if __name__ == "__main__":
    main()
