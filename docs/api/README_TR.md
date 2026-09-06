# PhishShield TR API Dokümantasyonu

## Genel Bakış

PhishShield TR API, URL'lerin phishing olup olmadığını analiz etmek için kapsamlı bir REST API sağlar. Türk bankaları, e-ticaret siteleri ve devlet kurumları için özelleştirilmiş koruma sunar.

**Base URL:** `http://127.0.0.1:8004`

## Kimlik Doğrulama

Tüm API istekleri `X-API-Key` header'ı ile kimlik doğrulama gerektirir:

```
X-API-Key: psh_your_api_key_here
```

### API Anahtarı Alma

API anahtarı almak için sistem yöneticinizle iletişime geçin.

## Rate Limiting

| Tier     | İstek/Dakika | İstek/Gün   |
|----------|--------------|-------------|
| Free     | 10           | 500         |
| Basic    | 60           | 5,000       |
| Premium  | 300          | 100,000     |
| Enterprise| 1,000       | 500,000     |

## Endpoints

### 1. URL Analizi

**POST** `/api/v2/check`

Bir URL'nin phishing olup olmadığını analiz eder.

#### Request Body

```json
{
  "url": "https://garanti-login-secure.xyz.com",
  "check_type": "full"
}
```

#### Response

```json
{
  "url": "https://garanti-login-secure.xyz.com",
  "domain": "garanti-login-secure.xyz.com",
  "decision": "PHISHING",
  "risk_score": 85,
  "confidence": 95,
  "components": {
    "threat": 100,
    "brand": 70,
    "form": 60,
    "domain": 30,
    "content": 20
  },
  "ml_confidence": 0.90,
  "ml_probability": 0.95,
  "threat_match": true,
  "threat_sources": ["openphish"],
  "signals": [
    {"signal": "Marka taklidi: Garanti", "severity": "high"},
    {"signal": "Harici form submit", "severity": "high"}
  ],
  "recommendations": [
    "Kişisel veya finansal bilgilerinizi girmeyin",
    "URL'yi tarayıcıda elle kontrol edin"
  ],
  "analysis_time_ms": 156,
  "timestamp": "2026-09-04T19:00:00Z"
}
```

---

### 2. Toplu URL Analizi

**POST** `/api/v2/batch`

Birden fazla URL'yi aynı anda analiz eder (max 100).

#### Request Body

```json
{
  "urls": [
    "https://google.com",
    "https://garanti-login.xyz",
    "https://akbank.com"
  ]
}
```

#### Response

```json
{
  "results": [
    {
      "url": "https://google.com",
      "decision": "SAFE",
      "risk_score": 5
    },
    {
      "url": "https://garanti-login.xyz",
      "decision": "PHISHING",
      "risk_score": 90
    },
    {
      "url": "https://akbank.com",
      "decision": "SAFE",
      "risk_score": 10
    }
  ],
  "summary": {
    "total": 3,
    "phishing": 1,
    "safe": 2,
    "suspicious": 0
  },
  "analysis_time_ms": 312
}
```

---

### 3. Detaylı Açıklama

**POST** `/api/v2/explain`

Bir analiz sonucunun detaylı insan okunabilir açıklamasını döndürür.

#### Request Body

```json
{
  "url": "https://garanti-login-secure.xyz.com",
  "risk_score": 85,
  "decision": "PHISHING",
  "components": {
    "threat": 100,
    "brand": 70,
    "form": 60,
    "domain": 30,
    "content": 20
  }
}
```

#### Response

```json
{
  "url": "https://garanti-login-secure.xyz.com",
  "headline": "⚠️ TEHLİKE! Bu site bilinen phishing adresi!",
  "summary": "Bu site, 85/100 risk skoru ile yüksek riskli olarak değerlendirildi. Birçok tehlike işareti tespit edildi.",
  "risk_level": "CRITICAL",
  "red_flags": [
    "Tehdit veritabanında (openphish)",
    "Marka taklidi: Garanti",
    "Form verisi harici adrese gönderiliyor",
    "Şüpheli TLD: .xyz"
  ],
  "component_explanations": {
    "threat_intel": "Site, bilinen phishing adresleri listesinde bulundu",
    "brand": "Garanti bankasının taklit edilmiş olması muhtemel",
    "form": "Kimlik bilgisi toplama formu tespit edildi",
    "domain": "Domain yapısı şüpheli (typosquat?)",
    "content": "İçerik analizi devam ediyor"
  },
  "advice": [
    "🔒 Kişisel veya finansal bilgilerinizi girmeyin",
    "🔗 URL'yi tarayıcıda elle yazarak gidin",
    "📞 Bankayı doğrudan arayarak doğrulayın"
  ],
  "breakdown": {
    "final_score": 85,
    "fusion_score": 80,
    "ml_probability": "90.0%",
    "fusion_weight": "70%",
    "ml_weight": "30%"
  }
}
```

---

### 4. Domain Zeka

**GET** `/api/v2/intel/domain/{domain}`

Bir domain hakkında detaylı bilgi getirir.

#### Response

```json
{
  "domain": "garanti-login-secure.xyz.com",
  "registrar": "NameCheap, Inc.",
  "registration_date": "2024-01-15",
  "expiration_date": "2025-01-15",
  "age_days": 597,
  "age_category": "new",
  "ssl_info": {
    "has_ssl": true,
    "issuer": "Let's Encrypt",
    "valid_from": "2024-06-01",
    "valid_until": "2024-08-30"
  },
  "dns_records": {
    "A": ["192.168.1.1"],
    "MX": ["mail.garanti-login-secure.xyz.com"],
    "NS": ["ns1.cloudprovider.com"]
  },
  "threat_intel": {
    "is_typosquat": true,
    "similar_domains": ["garanti.com.tr", "garanti.com"],
    "threat_match": true,
    "threat_sources": ["openphish", "urlhaus"]
  },
  "risk_factors": [
    {
      "factor": "Yeni domain (597 gün)",
      "risk_level": 20,
      "description": "Yeni kaydedilen domainler daha şüpheli"
    },
    {
      "factor": "Typosquat tespit edildi",
      "risk_level": 40,
      "description": "Garanti bankasına benzer domain"
    },
    {
      "factor": "Şüpheli TLD (.xyz)",
      "risk_level": 15,
      "description": "Ücretsiz/şüpheli TLD"
    }
  ]
}
```

---

### 5. Geri Bildirim

**POST** `/api/v2/feedback`

Bir analiz sonucu için geri bildirim gönderir. Bu veriler model iyileştirmesi için kullanılır.

#### Request Body

```json
{
  "url": "https://garanti-login-secure.xyz.com",
  "original_decision": "PHISHING",
  "original_score": 85,
  "feedback_type": "false_positive",
  "correct_label": "safe",
  "message": "Bu aslında Garanti'nin yeni kampanya sayfası"
}
```

#### Response

```json
{
  "success": true,
  "message": "Geri bildiriminiz için teşekkürler",
  "id": "fb_1234567890"
}
```

---

### 6. İstatistikler

**GET** `/api/v2/stats`

Sistem istatistiklerini döndürür.

#### Response

```json
{
  "total_requests": 125000,
  "phishing_detected": 15230,
  "safe_verified": 109500,
  "uptime_seconds": 2592000,
  "threat_db_size": 65891,
  "ml_model_version": "2.0.0-rf",
  "cache_hit_rate": 0.85,
  "avg_response_time_ms": 45.6
}
```

---

### 7. Sağlık Kontrolü

**GET** `/health`

Sistem sağlık durumunu kontrol eder.

#### Response

```json
{
  "status": "healthy",
  "components": {
    "threat_db": "online",
    "ml_model": "loaded",
    "cache": "ready"
  }
}
```

## Hata Kodları

| HTTP Kodu | Açıklama                              |
|-----------|---------------------------------------|
| 200       | Başarılı                              |
| 400       | Geçersiz istek parametreleri          |
| 401       | Geçersiz veya eksik API anahtarı      |
| 429       | Rate limit aşıldı                     |
| 500       | Sunucu hatası                         |

## Karar Değerleri

| Değer       | Açıklama                              |
|-------------|---------------------------------------|
| PHISHING    | Phishing olarak tespit edildi         |
| SAFE        | Güvenli olarak doğrulandı             |
| SUSPICIOUS  | Şüpheli, dikkatli olun                |

## Risk Skoru

- **0-30:** Düşük risk - Güvenli
- **31-60:** Orta risk - Dikkatli olun
- **61-80:** Yüksek risk - Muhtemelen tehlikeli
- **81-100:** Kritik risk - Kesinlikle tehlikeli
