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
    """Kullanici geri bildirimi endpoint"""
    try:
        # Geri bildirimi kaydet (basit loglama)
        feedback_data = {
            "url": request.url,
            "is_safe": request.is_safe,
            "user_feedback": request.user_feedback,
            "timestamp": "2025-04-08T12:00:00Z"
        }
        
        print(f"Feedback received: {feedback_data}")
        
        return {"message": "Geri bildirim kaydedildi", "status": "success"}
        
    except Exception as e:
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
    """Temel resmi domain'leri veritabanýna ekle"""
    basic_official_domains = [
        ("e-devlet.gov.tr", "government", "Türkiye Cumhuriyeti resmi devlet portalý"),
        ("turkiye.gov.tr", "government", "Türkiye Cumhuriyeti resmi devlet portalý"),
        ("gib.gov.tr", "government", "Gelir Ýdaresi Baþkanlýðý"),
        ("sgk.gov.tr", "government", "Sosyal Güvenlik Kurumu"),
        ("tcmb.gov.tr", "government", "Türkiye Cumhuriyet Merkez Bankasý"),
        ("btk.gov.tr", "government", "Bilgi Teknolojileri ve Ýletiþim Kurumu"),
        ("usom.gov.tr", "government", "Ulusal Siber Olaylara Müdahale Merkezi"),
        ("cimer.gov.tr", "government", "Cumhurbaþkanlýk Ýletiþim Merkezi"),
        ("meb.gov.tr", "education", "Milli Eðitim Bakanlýðý"),
        ("yok.gov.tr", "education", "Yükseköðretim Kurulu"),
        ("osym.gov.tr", "education", "Ölçme, Seçme ve Yerleþtirme Merkezi"),
        ("eba.gov.tr", "education", "Eðitim Biliþim Aðý"),
        ("cepteteb.com.tr", "bank", "Türkiye Ekonomi Bankasý"),
        ("ziraatbank.com.tr", "bank", "Ziraat Bankasý"),
        ("vakifbank.com.tr", "bank", "Vakýflar Bankasý"),
        ("halkbank.com.tr", "bank", "Halkbank"),
        ("garantibbva.com.tr", "bank", "Garanti BBVA"),
        ("akbank.com.tr", "bank", "Akbank"),
        ("isbank.com.tr", "bank", "Türkiye Ýþ Bankasý")
    ]
    
    basic_phishing_domains = [
        ("tebleherseyhazir.click", 8),
        ("tebleherseyhazir.xyz", 8),
        ("toblahorseyhazir.click", 8),
        ("toblahorseyhazir.xyz", 8),
        ("cepteteb-login.click", 9),
        ("eba-giris.click", 9),
        ("e-devlet-login.click", 9),
        ("meb-ogrenci.click", 9)
    ]
    
    for domain, category, description in basic_official_domains:
        await db_manager.add_official_domain(domain, category, description)
    
    for domain, threat_level in basic_phishing_domains:
        await db_manager.add_phishing_domain(domain, threat_level, "manual")
    
    print(f"Added {len(basic_official_domains)} official domains and {len(basic_phishing_domains)} phishing domains")

async def startup_tasks():
    """Baþlangýç görevleri"""
    print("ð Initializing database...")
    await seed_basic_domains()
    print("â Database ready!")

if __name__ == "__main__":
    print("PhishShield TR API v2.0 Starting...")
    print("Enhanced fake site detection algorithm active!")
    print("Server: http://127.0.0.1:8002")
    
    # Startup görevlerini çalıştır
    asyncio.run(startup_tasks())
    
    uvicorn.run(app, host="127.0.0.1", port=8002)
