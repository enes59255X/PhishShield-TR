# PhishShield TR 🛡️
**Yapay Zeka Destekli Phishing & Dolandırıcı Site Tespit Sistemi**

TrapSense Takımı | Hackathon 2025

---

## 📁 Proje Yapısı

```
phishshield-tr/
│
├── backend/
│   ├── app.py            → FastAPI ana uygulama
│   ├── analyzer.py       → URL/HTML/içerik analiz motoru
│   ├── intel.py          → Domain zekası, typo-squatting
│   ├── scoring.py        → Risk skoru & öneriler
│   ├── utils.py          → Yardımcı fonksiyonlar
│   ├── requirements.txt
│   └── data/
│       └── sample_dataset.json
│
└── extension/
    ├── manifest.json
    ├── popup.html
    ├── popup.css
    ├── popup.js
    └── icons/
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```

---

## 🚀 Kurulum & Çalıştırma

### 1. Backend Kurulumu

```bash
cd backend
pip install -r requirements.txt
python app.py
# → http://localhost:8000 üzerinde çalışır
```

**API Test:**
```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://garanti-bankasi-giris.xyz/login"}'
```

### 2. Chrome Extension Kurulumu

1. Chrome'u aç
2. `chrome://extensions/` adresine git
3. Sağ üstten **"Geliştirici modu"**nu aç
4. **"Paketlenmemiş uzantı yükle"** butonuna tıkla
5. `extension/` klasörünü seç
6. PhishShield TR ikonuna tıkla → analiz başlar

---

## 🔍 Sistem Nasıl Çalışır?

```
Kullanıcı Chrome'da site açar
        ↓
Extension aktif URL'yi alır
        ↓
Backend'e POST /analyze gönderilir
        ↓
analyzer.py çalışır:
  ├── URL & Domain analizi (intel.py)
  ├── HTML/Form analizi
  ├── Sosyal mühendislik içerik analizi
  └── Davranış analizi
        ↓
scoring.py toplam risk skoru üretir
        ↓
JSON response extension'a döner
        ↓
Popup'ta görsel sonuç gösterilir
```

---

## 📊 Risk Seviyeleri

| Skor | Seviye |
|------|--------|
| 0–19 | 🟢 Düşük Risk |
| 20–39 | 🟡 Orta Risk |
| 40–69 | 🟠 Yüksek Risk |
| 70–100 | 🔴 Kritik Risk |

---

## 🧠 Analiz Modülleri

| Modül | Ağırlık | Açıklama |
|-------|---------|----------|
| URL & Domain | %30 | Typo-squatting, şüpheli TLD, IP kullanımı |
| Form Analizi | %25 | Şifre/kart/IBAN alan tespiti |
| İçerik Analizi | %25 | Sosyal mühendislik metin kalıpları (TR+EN) |
| Davranış | %20 | Yönlendirme, SSL hatası, iframe |

---

## 🇹🇷 Yerli Katkı

PhishShield TR, Türkiye'ye özgü dolandırıcılık kalıplarını tanır:
- Sahte Garanti/Ziraat/İş Bankası sayfaları
- e-Devlet kimlik doğrulama taklitleri
- PTT/Yurtiçi/Aras kargo SMS dolandırıcılığı
- Trendyol/Hepsiburada ödül vaatleri
- Burs/çekiliş/kampanya aldatmacaları

---

## ⚙️ API Endpoint

```
POST /analyze
Content-Type: application/json
Body: { "url": "https://example.com" }

Response:
{
  "url": "...",
  "score": 0-100,
  "risk_level": "Düşük Risk | Orta Risk | Yüksek Risk | Kritik Risk",
  "threat_type": "Kimlik Avı | Sahte Giriş | Finansal Dolandırıcılık | Sosyal Mühendislik",
  "reasons": [...],
  "recommendations": [...],
  "sub_scores": { ... }
}
```
