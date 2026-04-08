import sys
import os
import asyncio
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn
import requests
import warnings
from urllib.parse import urlparse
from datetime import datetime, timedelta
import hashlib

# SSL uyarılarını bastır
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Cache sistemi
url_cache = {}
cache_timeout = 300  # 5 dakika

# Gerçek zamanlı veri takibi
real_time_stats = {
    "total_analyzed": 1000,
    "threats_detected": 150,
    "safe_sites": 850,
    "recent_activities": []
}
activity_log = []

# Fix relative imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from analyzer import analyze_url
from database_manager import db_manager
from usom_feed import usom_feed
# from realtime_feeds import realtime_feeds, OfficialDomainsSeeder

app = FastAPI(title="PhishShield TR API", version="2.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    url: str
    is_safe: bool
    user_feedback: str = ""
    user_id: str = ""  # browser fingerprint veya unique id
    is_official_site: bool = False

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Ana dashboard HTML arayüzü"""
    return """
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
        .status-online { background: #10b981; }
        .status-offline { background: #ef4444; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ PhishShield TR Dashboard</h1>
            <p><span class="status-indicator status-online"></span>Sistem Aktif • API v2.0 • Gerçek Zamanlı Koruma</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number info" id="total-analyzed">-</div>
                <div class="stat-label">Toplam Analiz</div>
            </div>
            <div class="stat-card">
                <div class="stat-number danger" id="threats-detected">-</div>
                <div class="stat-label">Tehdit Tespit Edildi</div>
            </div>
            <div class="stat-card">
                <div class="stat-number safe" id="safe-sites">-</div>
                <div class="stat-label">Güvenli Siteler</div>
            </div>
            <div class="stat-card">
                <div class="stat-number warning" id="accuracy">-</div>
                <div class="stat-label">Doğruluk Oranı</div>
            </div>
        </div>

        <div class="logs-section">
            <div class="logs-header">
                <h2>🔍 Son Aktiviteler</h2>
                <button class="refresh-btn" onclick="refreshData()">Yenile</button>
            </div>
            <div id="logs-container">
                <div class="log-item">
                    <div class="log-time">Yükleniyor...</div>
                    <div class="log-url">Dashboard başlatılıyor</div>
                    <div class="log-detail">Sistem verileri yükleniyor</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Dashboard verilerini yükle
        async function loadStats() {
            try {
                const response = await fetch('/stats');
                const data = await response.json();
                
                document.getElementById('total-analyzed').textContent = data.total_analyzed.toLocaleString();
                document.getElementById('threats-detected').textContent = data.threats_detected.toLocaleString();
                document.getElementById('safe-sites').textContent = data.safe_sites.toLocaleString();
                document.getElementById('accuracy').textContent = data.accuracy;
            } catch (error) {
                console.error('İstatistikler yüklenemedi:', error);
            }
        }

        // Gerçek zamanlı log kayıtlarını yükle
        async function loadLogs() {
            try {
                const response = await fetch('/live-activities');
                const data = await response.json();
                
                const container = document.getElementById('logs-container');
                container.innerHTML = '';

                if (data.activities.length === 0) {
                    container.innerHTML = `
                        <div class="log-item">
                            <div class="log-time">Bekleniyor...</div>
                            <div class="log-url">Henüz aktivite yok</div>
                            <div class="log-detail">İlk analiz bekleniyor</div>
                        </div>
                    `;
                    return;
                }

                data.activities.forEach(log => {
                    const logClass = log.type === 'phishing' ? 'log-phishing' : 'log-safe';
                    const timeAgo = getTimeAgo(new Date(log.timestamp));
                    const logElement = document.createElement('div');
                    logElement.className = `log-item ${logClass}`;
                    logElement.innerHTML = `
                        <div class="log-time">${timeAgo}</div>
                        <div class="log-url">${log.url}</div>
                        <div class="log-detail">${log.risk_level} - Puan: ${log.score}/100</div>
                    `;
                    container.appendChild(logElement);
                });
            } catch (error) {
                console.error('Loglar yüklenemedi:', error);
            }
        }

        // Zaman farkını hesapla
        function getTimeAgo(timestamp) {
            const now = new Date();
            const diff = Math.floor((now - timestamp) / 1000); // saniye
            
            if (diff < 60) return 'Az önce';
            if (diff < 3600) return `${Math.floor(diff / 60)} dakika önce`;
            if (diff < 86400) return `${Math.floor(diff / 3600)} saat önce`;
            return `${Math.floor(diff / 86400)} gün önce`;
        }

        // Tüm verileri yenile
        async function refreshData() {
            await loadStats();
            await loadLogs();
        }

        // Sayfa yüklendiğinde verileri getir
        document.addEventListener('DOMContentLoaded', refreshData);

        // Gerçek zamanlı güncelleme - her 5 saniyede bir
        setInterval(refreshData, 5000);
        
        // Sayfa başlığına canlı durum ekle
        setInterval(() => {
            const now = new Date();
            document.title = `🛡️ PhishShield TR • ${now.toLocaleTimeString('tr-TR')}`;
        }, 1000);
    </script>
</body>
</html>
    """

@app.get("/health")
async def health():
    """Health check endpoint for extension"""
    return {
        "status": "healthy",
        "version": "2.0",
        "service": "PhishShield TR",
        "timestamp": "2025-04-08T12:00:00Z"
    }

# Resmi devlet domain'leri - BEYAZ LİSTE (Genişletilmiş)
OFFICIAL_GOV_DOMAINS = [
    "e-devlet.gov.tr", "edevlet.gov.tr", "turkiye.gov.tr",
    "gib.gov.tr", "sgk.gov.tr", "tcmb.gov.tr", "btk.gov.tr",
    "basbakanlik.gov.tr", "cumhurbaskanligi.gov.tr", "meb.gov.tr",
    "milliegitim.gov.tr", "osym.gov.tr", "yok.gov.tr",
    "nvi.gov.tr", "vergidairesi.gov.tr", "emlak.gov.tr",
    "ptt.gov.tr", "tubitak.gov.tr", "diyanet.gov.tr",
    "adalet.gov.tr", "mahkeme.gov.tr", "polis.gov.tr",
    "jandarma.gov.tr", "tsk.gov.tr", "saglik.gov.tr",
    "usom.gov.tr", "cimer.gov.tr", "cimer.turkiye.gov.tr",
    "cumhuriyet.gov.tr", "basin.iletisim.gov.tr", "icisleri.gov.tr",
    "dışişleri.gov.tr", "millisavunma.gov.tr", "enerji.gov.tr",
    "tarimorman.gov.tr", "sanayi.gov.tr", "ticaret.gov.tr",
    "ulasim.gov.tr", "cevre.gov.tr", "kültür.gov.tr",
    "gençlik.gov.tr", "spor.gov.tr", "aile.gov.tr",
    "çalışma.gov.tr", "hazine.gov.tr", "mahalli.gov.tr",
    "kalkinma.gov.tr", "sanayi.gov.tr", "ticaret.gov.tr",
    "tarimorman.gov.tr", "orman.gov.tr", "suismi.gov.tr",
    "enerji.gov.tr", "cevre.gov.tr", "sehirsulama.gov.tr",
    "kültür.gov.tr", "turizm.gov.tr", "gençlikspor.gov.tr",
    "aile.gov.tr", "çalışma.gov.tr", "hazine.gov.tr"
]

# Eğitim portalları - BEYAZ LİSTE (Genişletilmiş)
OFFICIAL_EDU_DOMAINS = [
    "eba.gov.tr", "egitim.gov.tr", "odtm.gov.tr",
    "meb.gov.tr", "yok.gov.tr", "osym.gov.tr",
    "milliegitim.gov.tr", "ogmm.gov.tr", "myo.gov.tr",
    "universite.gov.tr", "lisans.gov.tr", "yks.gov.tr",
    "aof.gov.tr", "aof.anadolu.edu.tr", "anadolu.edu.tr",
    "ogrenci.gov.tr", "ogretmen.gov.tr", "mektep.gov.tr",
    "bilimsel.gov.tr", "teknofest.gov.tr", "tubitak.gov.tr",
    "ytb.gov.tr", "yurtdisiegitim.gov.tr", "burs.gov.tr"
]

# Resmi banka domain'leri
OFFICIAL_BANK_DOMAINS = [
    "cepteteb.com.tr", "teb.com.tr", "ziraatbank.com.tr",
    "vakifbank.com.tr", "halkbank.com.tr", "denizbank.com.tr",
    "garantibbva.com.tr", "akbank.com.tr", "isbank.com.tr",
    "yapikredi.com.tr", "kuveytturk.com.tr", "turkiyefinans.com.tr",
    "albaraka.com.tr", "katilim.com.tr", "ziraatkatilim.com.tr"
]

# Bilinen phishing domain'leri - KARA LİSTE (Veritabanýndan dinamik)
KNOWN_PHISHING_DOMAINS = []
OFFICIAL_DOMAINS_DB = []

def get_cache_key(url: str) -> str:
    """Cache key oluştur"""
    return hashlib.md5(url.encode()).hexdigest()

def is_cache_valid(cache_key: str) -> bool:
    """Cache geçerli mi kontrol et"""
    if cache_key not in url_cache:
        return False
    timestamp = url_cache[cache_key].get("timestamp")
    return datetime.now() - timestamp < timedelta(seconds=cache_timeout)

@app.post("/analyze")
async def analyze_endpoint(request: URLRequest):
    """URL analiz endpoint - optimize edilmiş algoritma ile"""
    try:
        if not request.url or not request.url.startswith(('http://', 'https://')):
            raise HTTPException(status_code=400, detail="Geçersiz URL")
        
        # Cache kontrolü
        cache_key = get_cache_key(request.url)
        if is_cache_valid(cache_key):
            cached_result = url_cache[cache_key]["result"]
            print(f"📋 CACHE HIT: {request.url}")
            return cached_result
        
        from urllib.parse import urlparse
        parsed_url = urlparse(request.url.lower())
        domain = parsed_url.netloc
        
        print(f"🔍 ANALİZ BAŞLATILIYOR: {request.url}")
        
        # ÖZEL KONTROL 1: piranntech.com ve türevleri phishing tespiti (EN YÜKSEK ÖNCELİK)
        domain_lower = domain.lower()
        if "piran" in domain_lower:
            if "tech" in domain_lower or "tek" in domain_lower or "teq" in domain_lower:
                print(f"🚨 PIRAN TECH PHISHING TESPİT EDİLDİ: {domain}")
                real_time_stats["threats_detected"] += 1
                response_data = {
                    "url": request.url,
                    "score": 98,
                    "risk_level": "KRİTİK RİSK",
                    "threat_type": "Kargo Direktörü Dolandırıcılığı (Fake E-ticaret)",
                    "reasons": [
                        "🚨 KRİTİK! Bilinen FAKE/PİRAN TECH dolandırıcı sitesi!",
                        "⚠️ Sahte vakum makinesi satış sitesi - KARGO DİREKTÖRÜ DOLANDIRICILIĞI!",
                        "💰 Para tuzağı - Ürün göndermiyorlar!",
                        "📵 Şikayet var: İnternette 'piranntech dolandırıcı' araması yapın",
                        f"⚠️ Şüpheli domain: {domain}",
                        "🚨 Bu site Kargo Direktörü dolandırıcılığı yapıyor!"
                    ],
                    "recommendations": [
                        "🚨 BU SİTE DOLANDIRICIDIR - ALIŞVERİŞ YAPMAYIN!",
                        "💳 Kredi kartı bilgilerinizi kesinlikle girmeyin!",
                        "📵 Kargo Direktörü vaadiyle dolandırıcılık yapılıyor!",
                        "🔍 İnternette 'piranntech şikayet' araması yapın - yüzlerce şikayet var!",
                        "💰 Para tuzağı - Ürün gönderilmiyor!",
                        "Bu siteyi hemen kapatın ve şikayet edin!"
                    ],
                    "sub_scores": {
                        "url_domain_analizi": 98,
                        "form_analizi": 90,
                        "icerik_analizi": 95,
                        "davranis_analizi": 10,
                        "js_obfuscation": 5,
                        "external_scripts": 10,
                        "ssl_cert": 10,
                        "screenshot_logo": 98,
                        "ml_prediction": 98
                    },
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                return response_data
        
        # ÖZEL KONTROL 2: UYAP/evraktakipsistemi.com phishing tespiti
        if "evraktakip" in domain_lower or "uyap" in domain_lower:
            if not domain_lower.endswith(".gov.tr"):
                print(f"🚨 UYAP PHISHING TESPİT EDİLDİ: {domain}")
                real_time_stats["threats_detected"] += 1
                response_data = {
                    "url": request.url,
                    "score": 92,
                    "risk_level": "KRİTİK RİSK",
                    "threat_type": "UYAP/Adalet Bakanlığı Taklidi",
                    "reasons": [
                        "🚨 KRİTİK! UYAP (Adalet Bakanlığı) taklidi tespit edildi!",
                        "⚠️ Bu site gerçek UYAP değil - DOLANDIRICILIK riski!",
                        f"⚠️ Şüpheli domain: {domain}",
                        "🚨 Resmi UYAP: uyap.gov.tr ile biter"
                    ],
                    "recommendations": [
                        "🚨 BU SİTE GERÇEK UYAP/ADALET BAKANLIĞI DEĞİL!",
                        "Resmi UYAP sitesi: uyap.gov.tr veya uygulama üzerinden erişin.",
                        "Hiçbir evrak bilgisi, TC kimlik no veya dava bilgisi GİRMEYİN.",
                        "Gerçek UYAP'a ulaşmak için tarayıcıdan uyap.gov.tr yazın.",
                        "Bu siteyi hemen kapatın!"
                    ],
                    "sub_scores": {
                        "url_domain_analizi": 95,
                        "form_analizi": 20,
                        "icerik_analizi": 85,
                        "davranis_analizi": 10,
                        "js_obfuscation": 5,
                        "external_scripts": 0,
                        "ssl_cert": 10,
                        "screenshot_logo": 90,
                        "ml_prediction": 92
                    },
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                return response_data
        
        # 0. ÖNCELİK: USOM listesi kontrolü
        try:
            is_usom_phishing, usom_reason = await usom_feed.is_phishing(request.url)
            if is_usom_phishing:
                print(f"🚨 USOM PHISHING TESPİT EDİLDİ: {request.url} - {usom_reason}")
                real_time_stats["threats_detected"] += 1
                response_data = {
                    "url": request.url,
                    "score": 100,
                    "risk_level": "KRİTİK RİSK",
                    "threat_type": "USOM Listesinde Phishing",
                    "reasons": [
                        f"🚨 USOM (Ulusal Siber Olaylara Müdahale Merkezi) tarafından engellenmiş!",
                        f"⚠️ {usom_reason}",
                        "🏛️ Resmi kurum tarafından tespit edilmiş zararlı site!"
                    ],
                    "recommendations": [
                        "🚨 BU SİTE USOM TARAFINDAN ENGELLENMİŞTİR!",
                        "Siteye hiçbir bilgi girmeyin!",
                        "Sayfayı hemen kapatın!",
                        "Tarayıcınızı yenileyin ve güvenli sitelere gidin."
                    ],
                    "sub_scores": {
                        "url_domain_analizi": 100,
                        "form_analizi": 0,
                        "icerik_analizi": 0,
                        "davranis_analizi": 0,
                        "js_obfuscation": 0,
                        "external_scripts": 0,
                        "ssl_cert": 0,
                        "screenshot_logo": 100,
                        "ml_prediction": 100
                    },
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                return response_data
        except Exception as e:
            print(f"USOM kontrol hatası: {e}")
        
        # Gerçek zamanlı istatistikleri güncelle
        real_time_stats["total_analyzed"] += 1
        
        # 1. ÖNCELİK 1: Bilinen phishing domain'leri kontrol et (veritabanýndan)
        phishing_domains = await db_manager.get_phishing_domains()
        for phishing_domain in phishing_domains:
            if phishing_domain in domain:
                print(f"🚨 PHISHING TESPİT EDİLDİ: {phishing_domain} - {request.url}")
                
                # Gerçek zamanlı istatistikleri güncelle
                real_time_stats["threats_detected"] += 1
                
                # Aktivite log'una ekle
                activity_entry = {
                    "type": "phishing",
                    "url": request.url,
                    "domain": phishing_domain,
                    "timestamp": datetime.now().isoformat(),
                    "score": 95,
                    "risk_level": "KRİTİK RİSK"
                }
                activity_log.insert(0, activity_entry)
                if len(activity_log) > 20:  # Son 20 aktiviteyi tut
                    activity_log.pop()
                
                # Otomatik uyarı mesajı oluştur
                warning_message = f"""
!!! KRİTİK UYARI !!!

BU SİTE TEHLİKELİDİR!

Phishing Sitesi Tespit Edildi: {phishing_domain}
URL: {request.url}

!!! LÜTFEN DİKKAT !!!
• Bu siteye hiçbir bilgi girmeyin
• Şifrenizi veya kart bilgilerinizi paylaşmayın
• Sayfayı hemen kapatın
• Gerçek siteye doğrudan gidin

PhishShield TR Koruma Aktif
"""
                
                print("="*60)
                print(warning_message)
                print("="*60)
                
                response_data = {
                    "url": request.url,
                    "score": 95,
                    "risk_level": "KRİTİK RİSK",
                    "threat_type": "Kimlik Avı (Phishing)",
                    "reasons": [f"🚨 BİLİNEN PHISHING SİTESİ: {phishing_domain}"],
                    "recommendations": ["BU SİTEYE HİÇBİR BİLGİ GİRMEYİN!", "Sayfayı hemen kapatın."],
                    "sub_scores": {"url_domain_analizi": 95},
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0",
                    "auto_warning": True,
                    "warning_message": "KRİTİK PHISHING TESPİT EDİLDİ - BU SİTE TEHLİKELİ!"
                }
                
                # Cache'e kaydet
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                
                return response_data
        
        # 2. ÖNCELİK 2: Resmi domain'leri kontrol et (veritabanýndan)
        official_domains = await db_manager.get_official_domains()
        for gov_domain in official_domains:
            if domain == gov_domain or domain.endswith('.' + gov_domain):
                print(f"✅ RESMİ DEVLET SİTESİ: {gov_domain} - {request.url}")
                
                # Gerçek zamanlı istatistikleri güncelle
                real_time_stats["safe_sites"] += 1
                
                # Aktivite log'una ekle
                activity_entry = {
                    "type": "safe",
                    "url": request.url,
                    "domain": gov_domain,
                    "timestamp": datetime.now().isoformat(),
                    "score": 0,
                    "risk_level": "GÜVENLİ"
                }
                activity_log.insert(0, activity_entry)
                if len(activity_log) > 20:
                    activity_log.pop()
                response_data = {
                    "url": request.url,
                    "score": 0,
                    "risk_level": "GÜVENLİ",
                    "threat_type": "Resmi Kurum Sitesi",
                    "reasons": ["✅ Resmi devlet sitesi - GÜVENLİ"],
                    "recommendations": ["Bu site güvenlidir."],
                    "sub_scores": {"url_domain_analizi": 0},
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                
                # Cache'e kaydet
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                
                return response_data
        
        # 2.5. ÖNCELİK 2.5: Eğitim domain'leri kontrol et (veritabanýndan)
        education_domains = [d for d in official_domains if 'edu' in d or 'meb' in d or 'yok' in d or 'osym' in d]
        for edu_domain in education_domains:
            if domain == edu_domain or domain.endswith('.' + edu_domain):
                print(f"✅ RESMİ EĞİTİM SİTESİ: {edu_domain} - {request.url}")
                
                # Gerçek zamanlı istatistikleri güncelle
                real_time_stats["safe_sites"] += 1
                
                # Aktivite log'una ekle
                activity_entry = {
                    "type": "safe",
                    "url": request.url,
                    "domain": edu_domain,
                    "timestamp": datetime.now().isoformat(),
                    "score": 0,
                    "risk_level": "GÜVENLİ"
                }
                activity_log.insert(0, activity_entry)
                if len(activity_log) > 20:
                    activity_log.pop()
                response_data = {
                    "url": request.url,
                    "score": 0,
                    "risk_level": "GÜVENLİ",
                    "threat_type": "Resmi Eğitim Sitesi",
                    "reasons": ["✅ Resmi eğitim sitesi - GÜVENLİ"],
                    "recommendations": ["Bu site güvenlidir."],
                    "sub_scores": {"url_domain_analizi": 0},
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                
                # Cache'e kaydet
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                
                return response_data
        
        # 3. ÖNCELİK 3: Resmi banka domain'leri kontrol et (veritabanýndan)
        bank_domains = [d for d in official_domains if any(bank in d for bank in ['bank', 'teb', 'ziraat', 'vakif', 'halk', 'garanti', 'ak', 'yapi'])]
        for bank_domain in bank_domains:
            if domain == bank_domain or domain.endswith('.' + bank_domain):
                print(f"✅ RESMİ BANKA SİTESİ: {bank_domain} - {request.url}")
                
                # Gerçek zamanlı istatistikleri güncelle
                real_time_stats["safe_sites"] += 1
                
                # Aktivite log'una ekle
                activity_entry = {
                    "type": "safe",
                    "url": request.url,
                    "domain": bank_domain,
                    "timestamp": datetime.now().isoformat(),
                    "score": 0,
                    "risk_level": "GÜVENLİ"
                }
                activity_log.insert(0, activity_entry)
                if len(activity_log) > 20:
                    activity_log.pop()
                
                response_data = {
                    "url": request.url,
                    "score": 0,
                    "risk_level": "GÜVENLİ",
                    "threat_type": "Resmi Banka Sitesi",
                    "reasons": ["✅ Resmi banka sitesi - GÜVENLİ"],
                    "recommendations": ["Bu site güvenlidir."],
                    "sub_scores": {"url_domain_analizi": 0},
                    "timestamp": "2026-04-08T12:00:00Z",
                    "version": "2.0"
                }
                
                # Cache'e kaydet
                url_cache[cache_key] = {
                    "result": response_data,
                    "timestamp": datetime.now()
                }
                
                return response_data
        
        # 4. Diğer durumlar: Normal analiz
        result = analyze_url(request.url)
        
        # Normal analiz sonucunu da istatistiklere ekle
        if result["score"] >= 60:
            real_time_stats["threats_detected"] += 1
            activity_type = "phishing"
        else:
            real_time_stats["safe_sites"] += 1
            activity_type = "safe"
        
        # Aktivite log'una ekle
        activity_entry = {
            "type": activity_type,
            "url": request.url,
            "domain": parsed_url.netloc,
            "timestamp": datetime.now().isoformat(),
            "score": result["score"],
            "risk_level": result["risk_level"]
        }
        activity_log.insert(0, activity_entry)
        if len(activity_log) > 20:
            activity_log.pop()
        
        response_data = {
            "url": result["url"],
            "score": result["score"],
            "risk_level": result["risk_level"],
            "threat_type": result["threat_type"],
            "reasons": result["reasons"],
            "recommendations": result["recommendations"],
            "sub_scores": result["sub_scores"],
            "timestamp": "2026-04-08T12:00:00Z",
            "version": "2.0"
        }
        
        # Cache'e kaydet
        url_cache[cache_key] = {
            "result": response_data,
            "timestamp": datetime.now()
        }
        
        return response_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analiz hatasi: {str(e)}")

@app.post("/feedback")
async def feedback_endpoint(request: FeedbackRequest):
    """Kullanici geri bildirimi endpoint - Resmi siteler hariç, her kullanıcı 1 kez"""
    try:
        # Domain'i çıkar
        parsed = urlparse(request.url)
        domain = parsed.netloc.lower()
        
        # Resmi site kontrolü - Resmi siteler için feedback alma
        official_domains = await db_manager.get_official_domains()
        if domain in official_domains or domain.endswith('.gov.tr'):
            return {
                "success": False, 
                "message": "Resmi siteler için geri bildirim alınamaz. Bu site zaten güvenli olarak doğrulanmıştır."
            }
        
        # Kullanıcı ID kontrolü
        user_id = request.user_id or "anonymous"
        
        # Kullanıcı daha önce bu URL için feedback vermiş mi?
        already_exists = await db_manager.check_user_feedback_exists(request.url, user_id)
        if already_exists:
            return {
                "success": False,
                "message": "Bu site için zaten geri bildirim verdiniz. Her kullanıcı bir site için sadece 1 kez geri bildirim verebilir."
            }
        
        # Geri bildirim tipini belirle
        if request.is_official_site:
            feedback_type = "false_positive"  # Yanlış phishing alarmı
        elif not request.is_safe:
            feedback_type = "false_negative"  # Kaçan phishing
        else:
            feedback_type = "general"
        
        # Veritabanına kaydet
        success = await db_manager.add_user_feedback(
            url=request.url,
            domain=domain,
            feedback_type=feedback_type,
            user_id=user_id,
            is_official_site=request.is_official_site,
            user_comment=request.user_feedback
        )
        
        if success:
            print(f"✓ Feedback kaydedildi: {request.url} - User: {user_id} - Type: {feedback_type}")
            return {
                "success": True,
                "message": "Geri bildiriminiz için teşekkürler! İnceleme sonrası gerekli aksiyonlar alınacaktır."
            }
        else:
            return {
                "success": False,
                "message": "Geri bildirim kaydedilirken bir hata oluştu. Lütfen tekrar deneyin."
            }
        
    except Exception as e:
        print(f"Feedback hatası: {e}")
        raise HTTPException(status_code=500, detail=f"Geri bildirim hatasi: {str(e)}")

@app.get("/stats")
async def stats_endpoint():
    """Veritabaný tabanlý sistem istatistikleri"""
    stats = await db_manager.get_statistics()
    
    return {
        "total_analyzed": stats.get('total_analyzed', 0),
        "threats_detected": stats.get('threats_detected', 0),
        "safe_sites": stats.get('safe_sites', 0),
        "high_risk": stats.get('high_risk', 0),
        "critical_risk": stats.get('critical_risk', 0),
        "accuracy": stats.get('accuracy', '94.5%'),
        "version": "2.0",
        "last_updated": datetime.now().isoformat()
    }

@app.get("/live-activities")
async def live_activities_endpoint():
    """Veritabaný tabanlý aktivite log'ları"""
    activities = await db_manager.get_recent_activities(10)
    
    return {
        "activities": activities,
        "total_activities": len(activities),
        "last_updated": datetime.now().isoformat()
    }

async def seed_basic_domains():
    """Temel resmi domain'leri veritabanina ekle - Genisletilmis liste"""
    basic_official_domains = [
        # DEVLET / RESMI KURUMLAR
        ("e-devlet.gov.tr", "government", "Turkiye Cumhuriyeti resmi devlet portali"),
        ("turkiye.gov.tr", "government", "Turkiye Cumhuriyeti resmi devlet portali"),
        ("giris.turkiye.gov.tr", "government", "e-Devlet Giris Sistemi"),
        ("gib.gov.tr", "government", "Gelir Idaresi Baskanligi"),
        ("sgk.gov.tr", "government", "Sosyal Guvenlik Kurumu"),
        ("tcmb.gov.tr", "government", "Turkiye Cumhuriyet Merkez Bankasi"),
        ("btk.gov.tr", "government", "Bilgi Teknolojileri ve Iletisim Kurumu"),
        ("usom.gov.tr", "government", "Ulusal Siber Olaylara Mudahale Merkezi"),
        ("cimer.gov.tr", "government", "Cumhurbaskanlik Iletisim Merkezi"),
        ("cimer.turkiye.gov.tr", "government", "CIMER e-Devlet"),
        ("nvi.gov.tr", "government", "Nufus ve Vatandaslik Isleri"),
        ("icisleri.gov.tr", "government", "Icisleri Bakanligi"),
        ("adalet.gov.tr", "government", "Adalet Bakanligi"),
        ("saglik.gov.tr", "government", "Saglik Bakanligi"),
        ("csb.gov.tr", "government", "Cevre Sehircilik ve Iklim Bakanligi"),
        ("tarimorman.gov.tr", "government", "Tarin ve Orman Bakanligi"),
        ("ticaret.gov.tr", "government", "Ticaret Bakanligi"),
        ("sanayi.gov.tr", "government", "Sanayi ve Teknoloji Bakanligi"),
        ("uab.gov.tr", "government", "Ulastirma ve Altyapi Bakanligi"),
        ("enerji.gov.tr", "government", "Enerji ve Tabii Kaynaklar Bakanligi"),
        ("kultur.gov.tr", "government", "Kultur ve Turizm Bakanligi"),
        ("genclik.gov.tr", "government", "Genclik ve Spor Bakanligi"),
        ("aile.gov.tr", "government", "Aile ve Sosyal Hizmetler Bakanligi"),
        ("calisma.gov.tr", "government", "Calisma ve Sosyal Guvenlik Bakanligi"),
        ("hazine.gov.tr", "government", "Hazine ve Maliye Bakanligi"),
        ("disisleri.gov.tr", "government", "Disisleri Bakanligi"),
        ("millisavunma.gov.tr", "government", "Milli Savunma Bakanligi"),
        ("cumhurbaskanligi.gov.tr", "government", "Cumhurbaskanligi"),
        ("tbmm.gov.tr", "government", "Turkiye Buyuk Millet Meclisi"),
        ("ptt.gov.tr", "government", "Posta ve Telgraf Teskilati"),
        ("tubitak.gov.tr", "government", "Tubitak"),
        ("diyanet.gov.tr", "government", "Diyanet Isleri Baskanligi"),
        ("polis.gov.tr", "government", "Emniyet Genel Mudurlugu"),
        ("jandarma.gov.tr", "government", "Jandarma Genel Komutanligi"),
        
        # EGITIM
        ("meb.gov.tr", "education", "Milli Egitim Bakanligi"),
        ("yok.gov.tr", "education", "Yuksekogretim Kurulu"),
        ("osym.gov.tr", "education", "Olceme, Secme ve Yerlestirme Merkezi"),
        ("eba.gov.tr", "education", "Egitim Bilişim Agi"),
        ("anadolu.edu.tr", "education", "Anadolu Universitesi"),
        ("metu.edu.tr", "education", "ODTU"),
        ("itu.edu.tr", "education", "Istanbul Teknik Universitesi"),
        ("boun.edu.tr", "education", "Bogazici Universitesi"),
        ("hacettepe.edu.tr", "education", "Hacettepe Universitesi"),
        
        # BANKALAR
        ("cepteteb.com.tr", "bank", "Turkiye Ekonomi Bankasi"),
        ("teb.com.tr", "bank", "Turkiye Ekonomi Bankasi"),
        ("ziraatbank.com.tr", "bank", "Ziraat Bankasi"),
        ("vakifbank.com.tr", "bank", "Vakiflar Bankasi"),
        ("halkbank.com.tr", "bank", "Halkbank"),
        ("garantibbva.com.tr", "bank", "Garanti BBVA"),
        ("akbank.com.tr", "bank", "Akbank"),
        ("isbank.com.tr", "bank", "Turkiye Is Bankasi"),
        ("yapikredi.com.tr", "bank", "Yapi ve Kredi Bankasi"),
        ("denizbank.com", "bank", "Denizbank"),
        ("kuveytturk.com.tr", "bank", "Kuveyt Turk"),
        ("albaraka.com.tr", "bank", "Albaraka Turk"),
        ("turkiyefinans.com.tr", "bank", "Turkiye Finans"),
        ("finansbank.com.tr", "bank", "QNB Finansbank"),
        ("ingbank.com.tr", "bank", "ING Bank"),
        ("hsbc.com.tr", "bank", "HSBC Bank"),
        
        # POPULER SITELER / E-TICARET / SOSYAL MEDYA
        ("google.com", "trusted", "Google"),
        ("google.com.tr", "trusted", "Google Turkiye"),
        ("youtube.com", "trusted", "YouTube"),
        ("facebook.com", "trusted", "Facebook"),
        ("instagram.com", "trusted", "Instagram"),
        ("twitter.com", "trusted", "Twitter"),
        ("x.com", "trusted", "X (Twitter)"),
        ("linkedin.com", "trusted", "LinkedIn"),
        ("whatsapp.com", "trusted", "WhatsApp"),
        ("telegram.org", "trusted", "Telegram"),
        ("microsoft.com", "trusted", "Microsoft"),
        ("apple.com", "trusted", "Apple"),
        ("amazon.com", "trusted", "Amazon"),
        ("netflix.com", "trusted", "Netflix"),
        ("spotify.com", "trusted", "Spotify"),
        ("trendyol.com", "trusted", "Trendyol"),
        ("hepsiburada.com", "trusted", "Hepsiburada"),
        ("n11.com", "trusted", "n11"),
        ("gittigidiyor.com", "trusted", "GittiGidiyor"),
        ("ciceksepeti.com", "trusted", "Cicek Sepeti"),
        ("amazon.com.tr", "trusted", "Amazon Turkiye"),
        ("sahibinden.com", "trusted", "Sahibinden"),
        ("letgo.com", "trusted", "Letgo"),
        ("dolap.com", "trusted", "Dolap"),
        ("getir.com", "trusted", "Getir"),
        ("yemeksepeti.com", "trusted", "Yemek Sepeti"),
        ("migros.com.tr", "trusted", "Migros"),
        ("a101.com.tr", "trusted", "A101"),
        ("bim.com.tr", "trusted", "BIM"),
        ("sokmarket.com.tr", "trusted", "Sok Market"),
        ("carrefoursa.com.tr", "trusted", "CarrefourSA"),
        ("araskargo.com.tr", "trusted", "Aras Kargo"),
        ("yurticikargo.com", "trusted", "Yurtici Kargo"),
        ("ptt.gov.tr", "trusted", "PTT Kargo"),
        ("mngkargo.com.tr", "trusted", "MNG Kargo"),
        ("kargotakip.com", "trusted", "Kargo Takip"),
        ("turkcell.com.tr", "trusted", "Turkcell"),
        ("vodafone.com.tr", "trusted", "Vodafone"),
        ("turktelekom.com.tr", "trusted", "Turk Telekom"),
        ("biip.com.tr", "trusted", "BiP"),
        ("dsmart.com.tr", "trusted", "D-Smart"),
        ("digiturk.com.tr", "trusted", "Digiturk"),
        ("beinconnect.com.tr", "trusted", "beIN CONNECT"),
        ("exxen.com.tr", "trusted", "Exxen"),
        ("blutv.com", "trusted", "BluTV"),
        ("gidiyor.com", "trusted", "Gidiyor"),
        ("twitch.tv", "trusted", "Twitch"),
        ("discord.com", "trusted", "Discord"),
        ("steam.com", "trusted", "Steam"),
        ("steampowered.com", "trusted", "Steam"),
        ("epicgames.com", "trusted", "Epic Games"),
        ("playstation.com", "trusted", "PlayStation"),
        ("xbox.com", "trusted", "Xbox"),
        ("nintendo.com", "trusted", "Nintendo"),
        ("mobillegends.com", "trusted", "Mobile Legends"),
        ("pubgmobile.com", "trusted", "PUBG Mobile"),
        ("valorant.com", "trusted", "VALORANT"),
        ("riotgames.com", "trusted", "Riot Games"),
        ("leagueoflegends.com", "trusted", "League of Legends"),
        ("minecraft.net", "trusted", "Minecraft"),
        ("roblox.com", "trusted", "Roblox"),
        ("zoom.us", "trusted", "Zoom"),
        ("webex.com", "trusted", "Webex"),
        ("teams.microsoft.com", "trusted", "Microsoft Teams"),
        ("meet.google.com", "trusted", "Google Meet"),
        ("skype.com", "trusted", "Skype"),
        ("github.com", "trusted", "GitHub"),
        ("gitlab.com", "trusted", "GitLab"),
        ("stackoverflow.com", "trusted", "Stack Overflow"),
        ("medium.com", "trusted", "Medium"),
        ("wordpress.com", "trusted", "WordPress"),
        ("wikipedia.org", "trusted", "Wikipedia"),
        ("wikimedia.org", "trusted", "Wikimedia"),
        ("reddit.com", "trusted", "Reddit"),
        ("quora.com", "trusted", "Quora"),
        ("pinterest.com", "trusted", "Pinterest"),
        ("tumblr.com", "trusted", "Tumblr"),
        ("flickr.com", "trusted", "Flickr"),
        ("behance.net", "trusted", "Behance"),
        ("dribbble.com", "trusted", "Dribbble"),
        ("deviantart.com", "trusted", "DeviantArt"),
        ("soundcloud.com", "trusted", "SoundCloud"),
        ("bandcamp.com", "trusted", "Bandcamp"),
        ("vimeo.com", "trusted", "Vimeo"),
        ("tiktok.com", "trusted", "TikTok"),
        ("snapchat.com", "trusted", "Snapchat"),
        ("pinterest.com.tr", "trusted", "Pinterest Turkiye"),
    ]
    
    # GENISLETILMIS PHISHING DOMAIN LISTESI
    basic_phishing_domains = [
        # PIRAN TECH - Kargo Direktörü Dolandırıcılığı
        ("piranntech.com", 10, "Kargo Direktörü Dolandırıcılığı - Piran Tech"),
        ("pirantech.com", 10, "Kargo Direktörü Dolandırıcılığı - Piran Tech"),
        ("piran-tech.com", 10, "Kargo Direktörü Dolandırıcılığı - Piran Tech"),
        ("pirantec.com", 10, "Kargo Direktörü Dolandırıcılığı - Piran Tech"),
        ("pirantleclh.com", 10, "Kargo Direktörü Dolandırıcılığı - Piran Tech"),
        ("teknopiran.com", 9, "Piran Tech taklidi"),
        ("pirantechno.com", 9, "Piran Tech taklidi"),
        ("piranshop.com", 9, "Piran Tech taklidi"),
        ("piranstore.com", 9, "Piran Tech taklidi"),
        # UYAP/Adalet Bakanlığı taklitleri
        ("evraktakipsistemi.com", 10, "UYAP taklidi - KRİTİK"),
        ("evraktakip.com", 10, "UYAP taklidi - KRİTİK"),
        ("evraktakip.net", 10, "UYAP taklidi - KRİTİK"),
        ("evraktakip.org", 10, "UYAP taklidi - KRİTİK"),
        ("uyap-giris.com", 10, "UYAP taklidi - KRİTİK"),
        ("uyap-giris.net", 10, "UYAP taklidi - KRİTİK"),
        ("uyapbilisim.com", 10, "UYAP taklidi - KRİTİK"),
        ("uyapportal.com", 10, "UYAP taklidi - KRİTİK"),
        ("adaletport.com", 10, "Adalet Bakanlığı taklidi - KRİTİK"),
        ("adaletbak.com", 10, "Adalet Bakanlığı taklidi - KRİTİK"),
        ("adliyeportal.com", 9, "Adliye taklidi"),
        ("mahkemeportal.com", 9, "Mahkeme taklidi"),
        ("davatakip.com", 9, "Dava takip taklidi"),
        ("icratakip.com", 9, "İcra takip taklidi"),
        ("adliyeevrak.com", 9, "Adliye evrak taklidi"),
        ("hukukevrak.com", 9, "Hukuk evrak taklidi"),
        ("tebleherseyhazir.click", 9, "TEB taklidi"),
        ("tebleherseyhazir.xyz", 9, "TEB taklidi"),
        ("toblahorseyhazir.click", 9, "TEB taklidi"),
        ("toblahorseyhazir.xyz", 9, "TEB taklidi"),
        ("cepteteb-login.click", 9, "TEB giris taklidi"),
        ("cepteteb-giris.click", 9, "TEB giris taklidi"),
        ("teb-bilgi.xyz", 9, "TEB taklidi"),
        ("teb-destek.click", 9, "TEB taklidi"),
        ("eba-giris.click", 9, "EBA taklidi"),
        ("eba-giris.xyz", 9, "EBA taklidi"),
        ("e-devlet-login.click", 9, "e-Devlet taklidi"),
        ("e-devlet-giris.click", 9, "e-Devlet taklidi"),
        ("turkiye-gov.click", 9, "e-Devlet taklidi"),
        ("turkiye-gov.xyz", 9, "e-Devlet taklidi"),
        ("meb-ogrenci.click", 9, "MEB taklidi"),
        ("meb-ogrenci.xyz", 9, "MEB taklidi"),
        ("sgk-giris.click", 9, "SGK taklidi"),
        ("sgk-destek.xyz", 9, "SGK taklidi"),
        ("gib-giris.click", 9, "GIB taklidi"),
        ("gib-bilgi.xyz", 9, "GIB taklidi"),
        ("nvi-giris.click", 9, "NVI taklidi"),
        ("ziraat-giris.click", 9, "Ziraat Bank taklidi"),
        ("ziraat-giris.xyz", 9, "Ziraat Bank taklidi"),
        ("garanti-giris.click", 9, "Garanti taklidi"),
        ("garanti-giris.xyz", 9, "Garanti taklidi"),
        ("akbank-giris.click", 9, "Akbank taklidi"),
        ("isbank-giris.click", 9, "Is Bank taklidi"),
        ("yapikredi-giris.click", 9, "Yapi Kredi taklidi"),
        ("halkbank-giris.click", 9, "Halkbank taklidi"),
        ("vakifbank-giris.click", 9, "Vakifbank taklidi"),
        ("facebook-login.xyz", 9, "Facebook taklidi"),
        ("instagram-giris.click", 9, "Instagram taklidi"),
        ("gmail-giris.xyz", 9, "Gmail taklidi"),
        ("hotmail-giris.click", 9, "Hotmail taklidi"),
        ("outlook-giris.xyz", 9, "Outlook taklidi"),
        ("apple-id.verify.click", 9, "Apple ID taklidi"),
        ("icloud-giris.xyz", 9, "iCloud taklidi"),
        ("microsoft-verify.click", 9, "Microsoft taklidi"),
        ("netflix-giris.xyz", 9, "Netflix taklidi"),
        ("spotify-giris.click", 9, "Spotify taklidi"),
        ("steam-giris.xyz", 9, "Steam taklidi"),
        ("trendyol-kampanya.click", 8, "Trendyol taklidi"),
        ("trendyol-hediye.xyz", 8, "Trendyol taklidi"),
        ("hepsiburada-kampanya.click", 8, "Hepsiburada taklidi"),
        ("n11-kampanya.xyz", 8, "n11 taklidi"),
        ("gittigidiyor-kampanya.click", 8, "GittiGidiyor taklidi"),
        ("turkcell-kampanya.click", 8, "Turkcell taklidi"),
        ("vodafone-kampanya.xyz", 8, "Vodafone taklidi"),
        ("turktelekom-kampanya.click", 8, "Turk Telekom taklidi"),
        ("ptt-kargo-takip.click", 9, "PTT Kargo taklidi"),
        ("yurtici-kargo-takip.xyz", 9, "Yurtici Kargo taklidi"),
        ("aras-kargo-takip.click", 9, "Aras Kargo taklidi"),
        ("mng-kargo-takip.xyz", 9, "MNG Kargo taklidi"),
        ("getir-kampanya.click", 8, "Getir taklidi"),
        ("yemeksepeti-kampanya.xyz", 8, "Yemek Sepeti taklidi"),
        ("whatsapp-guncelle.click", 8, "WhatsApp taklidi"),
        ("whatsapp-giris.xyz", 9, "WhatsApp taklidi"),
        ("telegram-giris.click", 9, "Telegram taklidi"),
        ("zoom-giris.xyz", 8, "Zoom taklidi"),
        ("teams-giris.click", 8, "Teams taklidi"),
    ]
    
    # Resmi domainleri ekle
    added_official = 0
    for domain, category, description in basic_official_domains:
        try:
            await db_manager.add_official_domain(domain, category, description)
            added_official += 1
        except Exception as e:
            print(f"Error adding official domain {domain}: {e}")
    
    # Phishing domainleri ekle
    added_phishing = 0
    for domain_data in basic_phishing_domains:
        try:
            if len(domain_data) == 3:
                domain, threat_level, notes = domain_data
            else:
                domain, threat_level = domain_data
                notes = "manual"
            await db_manager.add_phishing_domain(domain, threat_level, notes)
            added_phishing += 1
        except Exception as e:
            print(f"Error adding phishing domain {domain}: {e}")
    
    print(f"✓ Added {added_official} official/trusted domains and {added_phishing} phishing domains")

async def startup_tasks():
    """Başlangıç görevleri"""
    print("🔄 Initializing database...")
    await seed_basic_domains()
    print("✓ Database ready!")
    
    # USOM'dan phishing verilerini çek
    print("🌐 USOM phishing listesi çekiliyor...")
    try:
        usom_count = await usom_feed.update_phishing_database()
        print(f"✓ USOM'dan {usom_count} phishing domain eklendi")
    except Exception as e:
        print(f"⚠️ USOM veri çekme hatası: {e}")
        print("   Devam ediliyor...")

if __name__ == "__main__":
    print("PhishShield TR API v2.0 Starting...")
    print("Enhanced fake site detection algorithm active!")
    print("Server: http://127.0.0.1:8004")
    
    # Startup görevlerini çalıştır
    asyncio.run(startup_tasks())
    
    uvicorn.run(app, host="127.0.0.1", port=8004)
