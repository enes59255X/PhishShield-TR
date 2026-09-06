/**
 * PhishShield TR - API Client
 * Extension -> Backend iletisimi
 */

class PhishShieldClient {
  constructor(baseUrl = 'http://127.0.0.1:8004') {
    this.baseUrl = baseUrl;
    this.cache = new Map();
    this.cacheTTL = 5 * 60 * 1000; // 5 dakika
  }

  /**
   * URL'yi analiz et
   * @param {string} url - Analiz edilecek URL
   * @returns {Promise<Object>} Analiz sonucu
   */
  async analyze(url) {
    const cached = this.getCached(url);
    if (cached) {
      return { ...cached, cached: true };
    }

    try {
      const response = await fetch(`${this.baseUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const result = await response.json();
      this.setCached(url, result);
      return { ...result, cached: false };
    } catch (error) {
      console.error('PhishShield API Error:', error);
      return {
        decision: 'UNKNOWN',
        risk_score: 0,
        confidence: 0,
        error: error.message
      };
    }
  }

  /**
   * Sadece URL kararini al (hizli)
   * @param {string} url - Kontrol edilecek URL
   * @returns {Promise<Object>} Karar sonucu
   */
  async checkUrl(url) {
    const cached = this.getCached(url);
    if (cached) {
      return {
        decision: cached.decision,
        risk_score: cached.risk_score,
        confidence: cached.confidence,
        cached: true
      };
    }

    try {
      const response = await fetch(`${this.baseUrl}/analyze`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      const result = await response.json();
      this.setCached(url, result);
      return { ...result, cached: false };
    } catch (error) {
      console.error('PhishShield Check Error:', error);
      return {
        decision: 'UNKNOWN',
        risk_score: 0,
        confidence: 0,
        error: error.message
      };
    }
  }

  /**
   * Form analizi yap
   * @param {Object} formData - Form verileri
   * @returns {Promise<Object>} Form analiz sonucu
   */
  async analyzeForm(formData) {
    try {
      const response = await fetch(`${this.baseUrl}/analyze-form`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('PhishShield Form Analysis Error:', error);
      return {
        is_safe: false,
        risk_level: 'UNKNOWN',
        reasons: [error.message]
      };
    }
  }

  /**
   * Feedback gonder
   * @param {string} url - URL
   * @param {string} feedbackType - Feedback turu
   * @param {Object} details - Detaylar
   */
  async sendFeedback(url, feedbackType, details = {}) {
    try {
      await fetch(`${this.baseUrl}/feedback`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url,
          feedback_type: feedbackType,
          ...details
        }),
      });
      return true;
    } catch (error) {
      console.error('PhishShield Feedback Error:', error);
      return false;
    }
  }

  /**
   * Dashboard event gonder
   * @param {Object} eventData - Event verileri
   */
  async sendDashboardEvent(eventData) {
    try {
      await fetch(`${this.baseUrl}/events`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'extension_scan',
          timestamp: Date.now(),
          ...eventData
        }),
      });
      return true;
    } catch (error) {
      console.error('PhishShield Event Error:', error);
      return false;
    }
  }

  /**
   * Cache kontrol
   */
  getCached(url) {
    const entry = this.cache.get(url);
    if (!entry) return null;

    if (Date.now() - entry.timestamp > this.cacheTTL) {
      this.cache.delete(url);
      return null;
    }

    return entry.data;
  }

  /**
   * Cache'e kaydet
   */
  setCached(url, data) {
    this.cache.set(url, {
      data,
      timestamp: Date.now()
    });
  }

  /**
   * Cache'i temizle
   */
  clearCache() {
    this.cache.clear();
  }

  /**
   * Eski cache entireslerini temizle
   */
  cleanupCache() {
    const now = Date.now();
    for (const [url, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.cacheTTL) {
        this.cache.delete(url);
      }
    }
  }
}

// Global instance
const phishShieldAPI = new PhishShieldClient();
