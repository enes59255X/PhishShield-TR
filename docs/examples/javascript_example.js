/**
 * PhishShield TR API - JavaScript/Node.js Examples
 * 
 * Bu dosya API'nin JavaScript ile nasıl kullanılacağını gösterir.
 * 
 * Kurulum:
 * npm install node-fetch
 * 
 * veya fetch API kullanılabilir (Node.js 18+)
 */

const API_KEY = 'psh_your_api_key_here';
const BASE_URL = 'http://127.0.0.1:8004';

/**
 * PhishShield TR API Client
 */
class PhishShieldClient {
  constructor(apiKey, baseUrl = BASE_URL) {
    this.apiKey = apiKey;
    this.baseUrl = baseUrl;
  }

  /**
   * API isteği gönder
   */
  async request(endpoint, method = 'GET', body = null) {
    const options = {
      method,
      headers: {
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json'
      }
    };

    if (body) {
      options.body = JSON.stringify(body);
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, options);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'API request failed');
    }

    return response.json();
  }

  /**
   * URL analizi yap
   */
  async checkUrl(url, checkType = 'full') {
    return this.request('/api/v2/check', 'POST', {
      url,
      check_type: checkType
    });
  }

  /**
   * Toplu URL analizi yap
   */
  async batchCheck(urls) {
    return this.request('/api/v2/batch', 'POST', { urls });
  }

  /**
   * Detaylı açıklama al
   */
  async explain(url, riskScore, decision, components) {
    return this.request('/api/v2/explain', 'POST', {
      url,
      risk_score: riskScore,
      decision,
      components
    });
  }

  /**
   * Domain zeka bilgisi al
   */
  async getDomainIntel(domain) {
    return this.request(`/api/v2/intel/domain/${encodeURIComponent(domain)}`);
  }

  /**
   * Geri bildirim gönder
   */
  async submitFeedback(url, feedbackType, options = {}) {
    const data = {
      url,
      feedback_type: feedbackType,
      ...options
    };
    return this.request('/api/v2/feedback', 'POST', data);
  }

  /**
   * İstatistikleri al
   */
  async getStats() {
    return this.request('/api/v2/stats');
  }

  /**
   * Sağlık kontrolü yap
   */
  async healthCheck() {
    return this.request('/health');
  }
}


/**
 * Örnek Kullanımlar
 */

async function main() {
  const client = new PhishShieldClient(API_KEY);

  console.log('='.repeat(60));
  console.log('PhishShield TR API - JavaScript Örnekleri');
  console.log('='.repeat(60));

  // 1. URL Analizi
  console.log('\n1. URL Analizi:');
  console.log('-'.repeat(40));
  
  try {
    const result = await client.checkUrl('https://garanti-login-secure.xyz.com');
    console.log(`URL: ${result.url}`);
    console.log(`Karar: ${result.decision}`);
    console.log(`Risk Skoru: ${result.risk_score}`);
    console.log(`Güven: ${result.confidence}%`);
    
    // 2. Detaylı Açıklama
    console.log('\n2. Detaylı Açıklama:');
    console.log('-'.repeat(40));
    
    const explanation = await client.explain(
      result.url,
      result.risk_score,
      result.decision,
      result.components
    );
    console.log(`Başlık: ${explanation.headline}`);
    console.log(`Özet: ${explanation.summary}`);
    console.log('Kırmızı Bayraklar:');
    explanation.red_flags.forEach(flag => console.log(`  - ${flag}`));
    
  } catch (error) {
    console.error('Hata:', error.message);
  }

  // 3. Toplu Analiz
  console.log('\n3. Toplu URL Analizi:');
  console.log('-'.repeat(40));
  
  try {
    const batchResult = await client.batchCheck([
      'https://google.com',
      'https://akbank.com',
      'https://garanti-login.xyz'
    ]);
    console.log(`Toplam: ${batchResult.summary.total}`);
    console.log(`Phishing: ${batchResult.summary.phishing}`);
    console.log(`Güvenli: ${batchResult.summary.safe}`);
  } catch (error) {
    console.error('Hata:', error.message);
  }

  // 4. Domain Zeka
  console.log('\n4. Domain Zeka:');
  console.log('-'.repeat(40));
  
  try {
    const intel = await client.getDomainIntel('akbank.com');
    console.log(`Domain: ${intel.domain}`);
    console.log(`Yaş: ${intel.age_days} gün`);
    console.log(`SSL: ${intel.ssl_info.has_ssl ? 'Var' : 'Yok'}`);
  } catch (error) {
    console.error('Hata:', error.message);
  }

  // 5. Geri Bildirim
  console.log('\n5. Geri Bildirim:');
  console.log('-'.repeat(40));
  
  try {
    const feedback = await client.submitFeedback(
      'https://some-url.com',
      'false_positive',
      {
        original_decision: 'PHISHING',
        original_score: 75,
        message: 'Bu site güvenli'
      }
    );
    console.log(`Başarılı: ${feedback.success}`);
    console.log(`Mesaj: ${feedback.message}`);
  } catch (error) {
    console.error('Hata:', error.message);
  }

  // 6. İstatistikler
  console.log('\n6. Sistem İstatistikleri:');
  console.log('-'.repeat(40));
  
  try {
    const stats = await client.getStats();
    console.log(`Toplam İstek: ${stats.total_requests.toLocaleString()}`);
    console.log(`Phishing Tespit: ${stats.phishing_detected.toLocaleString()}`);
    console.log(`Threat DB: ${stats.threat_db_size.toLocaleString()}`);
  } catch (error) {
    console.error('Hata:', error.message);
  }

  // 7. Sağlık Kontrolü
  console.log('\n7. Sağlık Kontrolü:');
  console.log('-'.repeat(40));
  
  try {
    const health = await client.healthCheck();
    console.log(`Durum: ${health.status}`);
    console.log(`Bileşenler:`, health.components);
  } catch (error) {
    console.error('Hata:', error.message);
  }
}

// Module export (Node.js)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PhishShieldClient };
}

// Çalıştır
main().catch(console.error);
