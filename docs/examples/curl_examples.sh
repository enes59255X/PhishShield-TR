# PhishShield TR API - cURL Examples
# Bu dosya API'nin cURL ile nasıl kullanılacağını gösterir

# API anahtarınızı buraya girin
API_KEY="psh_your_api_key_here"
BASE_URL="http://127.0.0.1:8004"

# ============================================
# 1. URL Analizi
# ============================================

# Tek URL analizi
curl -X POST "${BASE_URL}/api/v2/check" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://garanti-login-secure.xyz.com"}'

# Hızlı analiz (daha az detay)
curl -X POST "${BASE_URL}/api/v2/check" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://suspicious-site.com", "check_type": "quick"}'

# ============================================
# 2. Toplu URL Analizi
# ============================================

curl -X POST "${BASE_URL}/api/v2/batch" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "urls": [
      "https://google.com",
      "https://akbank.com",
      "https://garanti-login.xyz"
    ]
  }'

# ============================================
# 3. Detaylı Açıklama
# ============================================

curl -X POST "${BASE_URL}/api/v2/explain" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
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
  }'

# ============================================
# 4. Domain Zeka
# ============================================

curl -X GET "${BASE_URL}/api/v2/intel/domain/garanti.com.tr" \
  -H "X-API-Key: ${API_KEY}"

# ============================================
# 5. Geri Bildirim
# ============================================

# Yanlış pozitif bildirimi (yanlışlıkla tehlikeli olarak işaretlendi)
curl -X POST "${BASE_URL}/api/v2/feedback" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://some-safe-site.com",
    "original_decision": "PHISHING",
    "original_score": 75,
    "feedback_type": "false_positive",
    "correct_label": "safe",
    "message": "Bu site aslında güvenli, yanlışlıkla engellendi"
  }'

# Yanlış negatif bildirimi (tehlikeli olarak tespit edilemedi)
curl -X POST "${BASE_URL}/api/v2/feedback" \
  -H "X-API-Key: ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://phishing-site123.xyz",
    "original_decision": "SAFE",
    "original_score": 20,
    "feedback_type": "false_negative",
    "correct_label": "phishing",
    "message": "Bu site phishing, hemen engellenmeli"
  }'

# ============================================
# 6. İstatistikler
# ============================================

curl -X GET "${BASE_URL}/api/v2/stats" \
  -H "X-API-Key: ${API_KEY}"

# ============================================
# 7. Sağlık Kontrolü
# ============================================

curl -X GET "${BASE_URL}/health" \
  -H "X-API-Key: ${API_KEY}"

# ============================================
# 8. Sistem Durumu
# ============================================

curl -X GET "${BASE_URL}/" \
  -H "X-API-Key: ${API_KEY}"
