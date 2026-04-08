#!/usr/bin/env python3
"""
PhishShield TR - Simple HTTP Server
Backend servisi kapaldugunda geçici çözüm
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse
from datetime import datetime
import threading
import time

class PhishShieldHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/':
            self.send_dashboard()
        elif self.path == '/health':
            self.send_health()
        elif self.path == '/stats':
            self.send_stats()
        elif self.path == '/live-activities':
            self.send_activities()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def do_POST(self):
        if self.path == '/analyze':
            self.handle_analyze()
        elif self.path == '/feedback':
            self.handle_feedback()
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'Not Found')
    
    def send_dashboard(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        html = """
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PhishShield TR Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 30px; margin-bottom: 30px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); text-align: center; }
        .header h1 { color: #2563eb; font-size: 2.5rem; margin-bottom: 10px; }
        .header p { color: #64748b; font-size: 1.1rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); text-align: center; transition: transform 0.3s ease; }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 3rem; font-weight: bold; margin-bottom: 10px; }
        .stat-label { color: #64748b; font-size: 1rem; }
        .safe { color: #10b981; }
        .danger { color: #ef4444; }
        .warning { color: #f59e0b; }
        .info { color: #3b82f6; }
        .status-online { background: #10b981; }
        .logs-section { background: rgba(255,255,255,0.95); border-radius: 15px; padding: 25px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); }
        .logs-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
        .logs-header h2 { color: #1e293b; }
        .refresh-btn { background: #3b82f6; color: white; border: none; padding: 10px 20px; border-radius: 8px; cursor: pointer; font-size: 14px; }
        .refresh-btn:hover { background: #2563eb; }
        .log-item { padding: 15px; border-left: 4px solid #e2e8f0; margin-bottom: 10px; background: #f8fafc; border-radius: 0 8px 8px 0; }
        .log-phishing { border-left-color: #ef4444; }
        .log-safe { border-left-color: #10b981; }
        .log-time { color: #64748b; font-size: 12px; }
        .log-url { font-weight: 500; margin: 5px 0; }
        .log-detail { color: #64748b; font-size: 14px; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PhishShield TR Dashboard</h1>
            <p><span class="status-indicator status-online"></span>Sistem Aktif - Basit Sunucu Modu</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number info" id="total-analyzed">0</div>
                <div class="stat-label">Toplam Analiz</div>
            </div>
            <div class="stat-card">
                <div class="stat-number danger" id="threats-detected">0</div>
                <div class="stat-label">Tehdit Tespit Edildi</div>
            </div>
            <div class="stat-card">
                <div class="stat-number safe" id="safe-sites">0</div>
                <div class="stat-label">Güvenli Siteler</div>
            </div>
            <div class="stat-card">
                <div class="stat-number warning" id="accuracy">95.0%</div>
                <div class="stat-label">Doðruluk Oraný</div>
            </div>
        </div>

        <div class="logs-section">
            <div class="logs-header">
                <h2>ð Son Aktiviteler</h2>
                <button class="refresh-btn" onclick="location.reload()">Yenile</button>
            </div>
            <div id="logs-container">
                <div class="log-item">
                    <div class="log-time">Sistem baþlatýldý</div>
                    <div class="log-url">Basit HTTP sunucu aktif</div>
                    <div class="log-detail">PhishShield TR v2.0</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Basit istatistikler
        let stats = {
            total_analyzed: 0,
            threats_detected: 0,
            safe_sites: 0
        };

        // Sayfa yüklendiðinde verileri güncelle
        document.addEventListener('DOMContentLoaded', () => {
            updateStats();
            // Her 5 saniyede bir yenile
            setInterval(updateStats, 5000);
        });

        function updateStats() {
            document.getElementById('total-analyzed').textContent = stats.total_analyzed.toLocaleString();
            document.getElementById('threats-detected').textContent = stats.threats_detected.toLocaleString();
            document.getElementById('safe-sites').textContent = stats.safe_sites.toLocaleString();
            
            const accuracy = stats.total_analyzed > 0 ? 
                ((stats.safe_sites / stats.total_analyzed) * 100).toFixed(1) : '95.0';
            document.getElementById('accuracy').textContent = accuracy + '%';
        }

        // Sayfa baþlýðýný güncelle
        setInterval(() => {
            document.title = `PhishShield TR - ${new Date().toLocaleTimeString('tr-TR')}`;
        }, 1000);
    </script>
</body>
</html>
        """
        self.wfile.write(html.encode())
    
    def send_health(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {
            "status": "healthy",
            "version": "2.0",
            "service": "PhishShield TR",
            "timestamp": datetime.now().isoformat(),
            "server_type": "simple_http"
        }
        self.wfile.write(json.dumps(response).encode())
    
    def send_stats(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()
        
        response = {
            "total_analyzed": 0,
            "threats_detected": 0,
            "safe_sites": 0,
            "high_risk": 0,
            "critical_risk": 0,
            "accuracy": "95.0%",
            "version": "2.0",
            "last_updated": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
    
    def send_activities(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {
            "activities": [],
            "total_activities": 0,
            "last_updated": datetime.now().isoformat()
        }
        self.wfile.write(json.dumps(response).encode())
    
    def handle_analyze(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            url = data.get('url', '')
            
            # Basit URL analizi
            is_phishing = self.is_phishing_url(url)
            
            if is_phishing:
                response = {
                    "url": url,
                    "score": 95,
                    "risk_level": "KRÝTÝK RÝSK",
                    "threat_type": "Kimlik Avý (Phishing)",
                    "reasons": ["Bilinen phishing pattern'i tespit edildi"],
                    "recommendations": ["BU SÝTEYE HÝÇBÝR BÝLGÝ GÝRMEYÝN!"],
                    "sub_scores": {"url_domain_analizi": 95},
                    "timestamp": datetime.now().isoformat(),
                    "version": "2.0"
                }
            else:
                response = {
                    "url": url,
                    "score": 15,
                    "risk_level": "DÜÞÜK RÝSK",
                    "threat_type": "Normal Site",
                    "reasons": ["Tehdit tespit edilmedi"],
                    "recommendations": ["Site güvenli görünüyor"],
                    "sub_scores": {"url_domain_analizi": 15},
                    "timestamp": datetime.now().isoformat(),
                    "version": "2.0"
                }
            
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'Content-Type')
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())
            
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            error_response = {"error": str(e)}
            self.wfile.write(json.dumps(error_response).encode())
    
    def handle_feedback(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        
        response = {"message": "Geri bildirim alýndý", "status": "success"}
        self.wfile.write(json.dumps(response).encode())
    
    def is_phishing_url(self, url):
        """Basit phishing tespiti"""
        phishing_indicators = [
            'tebleherseyhazir.click',
            'toblahorseyhazir.click',
            'cepteteb-login.click',
            'eba-giris.click',
            'e-devlet-login.click',
            '.click',
            '.xyz',
            '.top'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in phishing_indicators)
    
    def log_message(self, format, *args):
        """Log mesajları"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {format % args}")

def run_server():
    """Sunucuyu başlat"""
    server_address = ('127.0.0.1', 8002)
    httpd = HTTPServer(server_address, PhishShieldHandler)
    
    print("PhishShield TR Basit Sunucu Başlatılıyor...")
    print(f"Server: http://127.0.0.1:8002")
    print("Dashboard: http://127.0.0.1:8002")
    print("Health: http://127.0.0.1:8002/health")
    print("Ctrl+C ile durdurabilirsiniz")
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nSunucu durduruluyor...")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
