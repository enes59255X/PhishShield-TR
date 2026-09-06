# PhishShield TR V3

<div align="center">

![PhishShield TR](https://img.shields.io/badge/PhishShield-TR-v2.0-blue)
![Python](https://img.shields.io/badge/Python-3.11+-green)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100+-red)
![License](https://img.shields.io/badge/License-MIT-yellow)

**Türkiye'nin En Kapsamlı Gerçek Zamanlı Phishing Koruma Sistemi**

[Özellikler](#özellikler) • [Kurulum](#kurulum) • [API Kullanımı](#api-kullanımı) • [Mimari](#mimari) • [Geliştirme](#geliştirme)

</div>

---

## 🎯 Proje Hakkında

PhishShield TR, Türkiye'deki bankalar, e-ticaret siteleri ve devlet kurumları için özelleştirilmiş bir phishing tespit ve koruma sistemidir. Makine öğrenmesi, tehdit istihbaratı ve davranışsal analiz kombinasyonu ile %99'a varan doğruluk oranı sunar.

## ✨ Özellikler

### 🤖 Gelişmiş Tespit

- **Makine Öğrenmesi**: RandomForest algoritması ile hibrit analiz
- **Tehdit İstihbaratı**: OpenPhish, URLhaus, USOM entegrasyonu
- **Marka Taklidi Tespiti**: Türk bankaları ve kurumları için özelleştirilmiş
- **Davranışsal Analiz**: Form submit pattern'leri, domain yaşı, SSL analizi

### 📊 Çok Katmanlı Koruma

```
┌─────────────────────────────────────────────────────────────┐
│                    PhishShield TR V3                        │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Threat Intel (OpenPhish, URLhaus, USOM)          │
│  Layer 2: ML Hybrid Analyzer (RandomForest + Rules)       │
│  Layer 3: Brand Protection (Türk Bankaları)               │
│  Layer 4: Form Analysis (Credential Harvesting)           │
│  Layer 5: Domain Intelligence (Typosquat, Age, SSL)       │
│  Layer 6: Content Analysis (Page Content Review)          │
└─────────────────────────────────────────────────────────────┘
```

### 🔌 Entegrasyonlar

- **REST API**: Kolay entegrasyon için RESTful API
- **Browser Extension**: Chrome/Firefox için tarayıcı eklentisi
- **Mobile App**: iOS/Android için mobil uygulama
- **Webhook**: Anlık bildirimler için webhook desteği

### 📈 Sistem İstatistikleri

| Metrik | Değer |
|--------|-------|
| Threat DB Boyutu | 65,000+ domain |
| Ortalama Analiz Süresi | <100ms |
| Doğruluk Oranı | %99+ |
| Redis Önbellek | %85+ hit rate |
| API Yanıt Süresi | <50ms |

## 🏗️ Mimari

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENTS                               │
│  ┌─────────┐  ┌─────────────┐  ┌─────────┐  ┌──────────┐  │
│  │   Web   │  │  Extension  │  │ Mobile  │  │   API    │  │
│  └────┬────┘  └──────┬──────┘  └────┬────┘  └────┬─────┘  │
└───────┼──────────────┼──────────────┼─────────────┼────────┘
        │              │              │             │
        └──────────────┴──────────────┴─────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                     LOAD BALANCER                           │
│                      (Nginx)                                 │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                   PHISHSHIELD BACKEND                        │
│  ┌─────────────┐  ┌──────────────┐  ┌─────────────────┐   │
│  │  FastAPI    │  │  ML Engine   │  │  Intel Fusion    │   │
│  │  (Uvicorn)  │  │  (RandomForest)│ │  Engine          │   │
│  └──────┬──────┘  └──────┬───────┘  └────────┬────────┘   │
│         │                │                    │             │
│  ┌──────┴────────────────┴────────────────────┴────────┐   │
│  │                    ANALYSIS PIPELINE                 │   │
│  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │   │
│  │  │ Threat  │ │  Brand  │ │  Form   │ │ Domain  │   │   │
│  │  │  Intel  │ │Matcher  │ │Analyzer │ │ Intel   │   │   │
│  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘   │   │
│  └──────────────────────────────────────────────────────┘   │
└─────────────────────────┬───────────────────────────────────┘
                          │
         ┌────────────────┼────────────────┐
         │                │                │
         ▼                ▼                ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────────┐
│   Redis     │  │ PostgreSQL │  │   ML Models     │
│   Cache     │  │   Database │  │   (Pickle)      │
└─────────────┘  └─────────────┘  └─────────────────┘
```

## 📁 Proje Yapısı

```
PhishShield-TR/
├── backend/
│   ├── api/                    # API endpoints
│   │   ├── routes.py          # Route definitions
│   │   └── dependencies.py    # Auth & dependencies
│   ├── core/                   # Core functionality
│   │   ├── analyzer.py         # Main analyzer
│   │   ├── decision.py         # Decision engine
│   │   └── hybrid.py          # Hybrid scoring
│   ├── ml/                     # Machine Learning
│   │   ├── trainer.py          # Model training
│   │   ├── predictor.py        # Predictions
│   │   └── features.py         # Feature extraction
│   ├── intelligence/           # Threat Intelligence
│   │   ├── threat_feed.py      # Threat sources
│   │   ├── domain_intel.py     # Domain analysis
│   │   └── brandMatcher.py     # Brand protection
│   ├── forms/                  # Form Analysis
│   │   └── analyzer.py         # Form detection
│   ├── monitoring/             # Real-time monitoring
│   │   ├── dashboard.py        # Dashboard
│   │   ├── alerting.py         # Alerts
│   │   └── realtime.py         # WebSocket/SSE
│   ├── learning/               # Continuous Learning
│   │   ├── collector.py        # Data collection
│   │   ├── dataset.py          # Dataset management
│   │   └── trainer.py          # Online training
│   ├── security/               # Production Security
│   │   ├── api_security.py    # JWT & API keys
│   │   └── rate_limiter.py     # Rate limiting
│   ├── database/               # Database Layer
│   │   ├── models.py           # SQLAlchemy models
│   │   └── migrations.py       # DB migrations
│   └── tests/                  # Tests
│       └── regression/         # Regression tests
│
├── extension/                  # Browser Extension V2
│   ├── manifest.json
│   ├── background/
│   │   └── service_worker.js
│   ├── content/
│   │   ├── detector.js
│   │   └── form_guard.js
│   └── popup/
│       └── popup.html/js/css
│
├── mobile/                     # Flutter Mobile App
│   └── lib/
│       ├── main.dart
│       ├── models/
│       ├── services/
│       └── screens/
│
├── docker/                    # Docker Deployment
│   ├── docker-compose.yml
│   ├── backend/
│   │   └── Dockerfile
│   ├── nginx/
│   │   └── nginx.conf
│   └── postgres/
│       └── init.sql
│
├── docs/                       # Documentation
│   ├── api/
│   │   ├── openapi.json       # OpenAPI spec
│   │   └── README_TR.md       # API docs
│   └── examples/              # Code examples
│       ├── python_example.py
│       ├── javascript_example.js
│       └── curl_examples.sh
│
└── ml/
    └── models/                # Trained ML models
```

## 🚀 Kurulum

### Gereksinimler

- Python 3.11+
- Redis 7+ (önbellek için)
- PostgreSQL 15+ (veritabanı için)
- Node.js 18+ (browser extension için)
- Flutter 3+ (mobil uygulama için)

### Backend Kurulumu

```bash
# Backend dizinine gir
cd backend

# Virtual environment oluştur
python -m venv venv
source venv/bin/activate  # Linux/Mac
# veya
.\venv\Scripts\activate   # Windows

# Bağımlılıkları yükle
pip install -r requirements.txt

# Environment değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle

# Backend'i çalıştır
uvicorn main:app --reload --host 0.0.0.0 --port 8004
```

### Docker ile Kurulum

```bash
# Docker Compose ile tüm servislari başlat
docker-compose up -d

# Logs izle
docker-compose logs -f backend
```

### Environment Değişkenleri

```env
# .env dosyası
DATABASE_URL=postgresql://user:pass@localhost:5432/phishshield
REDIS_URL=redis://localhost:6379/0
SECRET_KEY=your-secret-key-here
DEBUG=false
LOG_LEVEL=INFO
```

## 📖 API Kullanımı

### Kimlik Doğrulama

```bash
# API anahtarınızı X-API-Key header'ında gönderin
curl -X POST "http://127.0.0.1:8004/api/v2/check" \
  -H "X-API-Key: psh_your_api_key_here" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://garanti-login-secure.xyz.com"}'
```

### URL Analizi

```python
import requests

url = "https://garanti-login-secure.xyz.com"
response = requests.post(
    "http://127.0.0.1:8004/api/v2/check",
    headers={"X-API-Key": "psh_your_key"},
    json={"url": url}
)

result = response.json()
print(f"Karar: {result['decision']}")
print(f"Risk Skoru: {result['risk_score']}")
```

### Detaylı Açıklama

```python
# Analiz sonucunun detaylı açıklamasını al
response = requests.post(
    "http://127.0.0.1:8004/api/v2/explain",
    headers={"X-API-Key": "psh_your_key"},
    json={
        "url": result["url"],
        "risk_score": result["risk_score"],
        "decision": result["decision"],
        "components": result["components"]
    }
)

explanation = response.json()
print(explanation["headline"])  # ⚠️ TEHLİKE! Bu site bilinen phishing adresi!
```

Daha fazla örnek için [docs/examples/](docs/examples/) dizinine bakın.

## 🧪 Test

```bash
# Tüm regresyon testlerini çalıştır
cd backend
python -m pytest tests/regression/ -v

# Belirli test dosyasını çalıştır
python tests/regression/test_sprint12.py
```

## 📊 Test Sonuçları

| Sprint | Modül | Test Sayısı | Durum |
|--------|-------|-------------|-------|
| 4 | Threat Intel | 10 | ✅ |
| 5 | Form Analysis | 13 | ✅ |
| 6 | ML Pipeline | 5 | ✅ |
| 7.1 | Feature Pipeline | 9 | ✅ |
| 7.2 | Fusion Engine | 8 | ✅ |
| 7.3 | Confidence Engine | 9 | ✅ |
| 8 | USOM Integration | 8 | ✅ |
| 9 | Intelligence Fusion | 9 | ✅ |
| 10 | ML Hybrid | 9 | ✅ |
| 11 | Domain Intelligence | 12 | ✅ |
| 12 | Explanation Engine | 12 | ✅ |
| 13 | Learning System | 17 | ✅ |
| 14 | Realtime Dashboard | 18 | ✅ |
| 14 | Browser Extension V2 | 15 | ✅ |
| 15 | Mobile App | 15 | ✅ |
| 16 | Production Security | 20 | ✅ |
| 17 | Documentation | - | ✅ |
| **Toplam** | | **214** | **✅** |

## 🛡️ Güvenlik

### Üretim Ortamı

- [x] JWT Token Authentication
- [x] API Key Management
- [x] Rate Limiting (Token Bucket + Sliding Window)
- [x] PostgreSQL ile Kalıcı Veri
- [x] Redis ile Önbellekleme
- [x] Nginx ile Ters Vekil
- [x] Docker İzolasyonu

### Rate Limit Tiers

| Tier | İstek/Dakika | İstek/Gün |
|------|--------------|-----------|
| Free | 10 | 500 |
| Basic | 60 | 5,000 |
| Premium | 300 | 100,000 |
| Enterprise | 1,000 | 500,000 |

## 📝 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 🤝 Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun (`git checkout -b feature/yeni-ozellik`)
3. Commit yapın (`git commit -am 'Yeni özellik eklendi'`)
4. Push yapın (`git push origin feature/yeni-ozellik`)
5. Pull Request açın

## 📧 İletişim

- **Website**: [phishshield.tr](https://phishshield.tr)
- **Email**: info@phishshield.tr

---

<div align="center">

**PhishShield TR - Türkiye'nin Phishing Koruma Kalkanı** 🛡️

</div>
