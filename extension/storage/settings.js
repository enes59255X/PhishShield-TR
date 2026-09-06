/**
 * PhishShield TR - Storage & Settings Manager
 */

class PhishShieldSettings {
  constructor() {
    this.defaults = {
      protectionEnabled: true,
      formProtection: true,
      autoScan: true,
      advancedMode: false,
      notificationsEnabled: true,
      cacheTTL: 5 * 60 * 1000, // 5 dakika
      apiUrl: 'http://127.0.0.1:8004'
    };
  }

  /**
   * Ayarlari yukle
   */
  async load() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['phishshield_settings'], (result) => {
        const settings = { ...this.defaults, ...result.phishshield_settings };
        resolve(settings);
      });
    });
  }

  /**
   * Ayarlari kaydet
   */
  async save(settings) {
    return new Promise((resolve) => {
      chrome.storage.local.set({
        phishshield_settings: { ...this.defaults, ...settings }
      }, resolve);
    });
  }

  /**
   * Ayar guncelle
   */
  async update(key, value) {
    const settings = await this.load();
    settings[key] = value;
    await this.save(settings);
    return settings;
  }

  /**
   * Ayar al
   */
  async get(key) {
    const settings = await this.load();
    return settings[key];
  }

  /**
   * Varsayilana sifirla
   */
  async reset() {
    return new Promise((resolve) => {
      chrome.storage.local.set({
        phishshield_settings: this.defaults
      }, resolve);
    });
  }
}

/**
 * Cache yonetimi
 */
class PhishShieldCache {
  constructor() {
    this.prefix = 'phishshield_cache_';
    this.defaultTTL = 5 * 60 * 1000; // 5 dakika
  }

  /**
   * Cache'e kaydet
   */
  set(key, value, ttl = this.defaultTTL) {
    const entry = {
      value,
      expires: Date.now() + ttl
    };
    chrome.storage.local.set({
      [this.prefix + key]: entry
    });
  }

  /**
   * Cache'den al
   */
  get(key) {
    return new Promise((resolve) => {
      chrome.storage.local.get([this.prefix + key], (result) => {
        const entry = result[this.prefix + key];
        
        if (!entry) {
          resolve(null);
          return;
        }

        if (Date.now() > entry.expires) {
          this.remove(key);
          resolve(null);
          return;
        }

        resolve(entry.value);
      });
    });
  }

  /**
   * Cache'den sil
   */
  remove(key) {
    chrome.storage.local.remove([this.prefix + key]);
  }

  /**
   * Tum cache'i temizle
   */
  clear() {
    chrome.storage.local.get(null, (items) => {
      const keysToRemove = Object.keys(items)
        .filter(key => key.startsWith(this.prefix));
      chrome.storage.local.remove(keysToRemove);
    });
  }

  /**
   * Eski entry'leri temizle
   */
  cleanup() {
    chrome.storage.local.get(null, (items) => {
      const now = Date.now();
      const keysToRemove = [];

      for (const [key, entry] of Object.entries(items)) {
        if (key.startsWith(this.prefix) && entry.expires && now > entry.expires) {
          keysToRemove.push(key);
        }
      }

      if (keysToRemove.length > 0) {
        chrome.storage.local.remove(keysToRemove);
      }
    });
  }
}

/**
 * Istatistik yonetimi
 */
class PhishShieldStats {
  constructor() {
    this.prefix = 'phishshield_stats_';
  }

  /**
   * Analiz sayisi artir
   */
  incrementAnalysis(decision) {
    chrome.storage.local.get(['phishshield_stats'], (result) => {
      const stats = result.phishshield_stats || {
        today: 0,
        total: 0,
        byDecision: {},
        lastReset: this.getTodayStart()
      };

      // Yeni gun kontrolu
      const todayStart = this.getTodayStart();
      if (stats.lastReset < todayStart) {
        stats.today = 0;
        stats.lastReset = todayStart;
      }

      stats.today++;
      stats.total++;
      stats.byDecision[decision] = (stats.byDecision[decision] || 0) + 1;

      chrome.storage.local.set({ phishshield_stats: stats });
    });
  }

  /**
   * Istatistikleri al
   */
  get() {
    return new Promise((resolve) => {
      chrome.storage.local.get(['phishshield_stats'], (result) => {
        resolve(result.phishshield_stats || {
          today: 0,
          total: 0,
          byDecision: {}
        });
      });
    });
  }

  /**
   * Bugunun baslangic timestamp'i
   */
  getTodayStart() {
    const now = new Date();
    return new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  }
}

// Global instances
const phishShieldSettings = new PhishShieldSettings();
const phishShieldCache = new PhishShieldCache();
const phishShieldStats = new PhishShieldStats();

// Periyodik temizlik
setInterval(() => {
  phishShieldCache.cleanup();
}, 60000); // Her dakika
