/**
 * PhishShield TR - Background Service Worker
 * URL monitoring ve tab takibi
 */

// API Client (inlined for Manifest V3 compatibility)
class PhishShieldClient {
  constructor(baseUrl = 'http://127.0.0.1:8004') {
    this.baseUrl = baseUrl;
    this.cache = new Map();
    this.cacheTTL = 5 * 60 * 1000;
  }

  async analyze(url) {
    const cached = this.getCached(url);
    if (cached) return { ...cached, cached: true };

    try {
      const response = await fetch(`${this.baseUrl}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
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

  async sendFeedback(url, feedbackType, details = {}) {
    try {
      await fetch(`${this.baseUrl}/feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, feedback_type: feedbackType, ...details }),
      });
      return true;
    } catch (error) {
      console.error('PhishShield Feedback Error:', error);
      return false;
    }
  }

  async sendDashboardEvent(eventData) {
    try {
      await fetch(`${this.baseUrl}/events`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 'extension_scan', timestamp: Date.now(), ...eventData }),
      });
      return true;
    } catch (error) {
      return false;
    }
  }

  getCached(url) {
    const entry = this.cache.get(url);
    if (!entry) return null;
    if (Date.now() - entry.timestamp > this.cacheTTL) {
      this.cache.delete(url);
      return null;
    }
    return entry.data;
  }

  setCached(url, data) {
    this.cache.set(url, { data, timestamp: Date.now() });
  }

  clearCache() { this.cache.clear(); }
  cleanupCache() {
    const now = Date.now();
    for (const [url, entry] of this.cache.entries()) {
      if (now - entry.timestamp > this.cacheTTL) this.cache.delete(url);
    }
  }
}

const phishShieldAPI = new PhishShieldClient();

// State
let currentTabUrl = null;
let lastAnalysis = null;
let settings = {
  protectionEnabled: true,
  formProtection: true,
  autoScan: true,
  advancedMode: false
};

// Load settings from storage
chrome.storage.local.get(['phishshield_settings'], (result) => {
  if (result.phishshield_settings) {
    settings = { ...settings, ...result.phishshield_settings };
  }
});

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) {
    handleTabUpdate(tabId, tab.url);
  }
});

// Listen for tab activation
chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab.url) handleTabUpdate(activeInfo.tabId, tab.url);
  } catch (error) {
    console.error('Tab activation error:', error);
  }
});

// Listen for navigation events
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) {
    handleTabUpdate(details.tabId, details.url);
  }
});

async function handleTabUpdate(tabId, url) {
  if (!settings.protectionEnabled || !settings.autoScan) return;
  if (!isHttpUrl(url)) return;

  currentTabUrl = url;

  try {
    const result = await phishShieldAPI.analyze(url);
    lastAnalysis = result;

    updateBadge(tabId, result.decision || mapScoreToDecision(result.score));

    chrome.runtime.sendMessage({
      type: 'ANALYSIS_RESULT',
      url,
      result
    }).catch(() => {});

    if (result.decision !== 'UNKNOWN') {
      phishShieldAPI.sendDashboardEvent({
        url,
        decision: result.decision,
        risk_score: result.risk_score || result.score,
        source: 'extension'
      });
    }

    if (result.decision === 'DANGER' || result.decision === 'BLOCK') {
      showDangerNotification(tabId, url, result);
      // Tehlikeli siteye tam sayfa uyarı göster
      showDangerWarningPage(tabId, url, result);
    }
  } catch (error) {
    console.error('Analysis error:', error);
  }
}

function showDangerWarningPage(tabId, url, result) {
  if (!settings.protectionEnabled) return;

  const domain = extractDomain(url);
  const score = result.risk_score || result.score || 100;
  const reasons = (result.reasons || ['Phishing site olarak tespit edildi']).join(',');

  // Uyarı sayfasına yönlendir
  const warningUrl = chrome.runtime.getURL(`../warning/warning.html`) +
    `?domain=${encodeURIComponent(domain)}` +
    `&score=${score}` +
    `&reasons=${encodeURIComponent(reasons)}`;

  // Mevcut sekmeyi uyarı sayfasına yönlendir
  chrome.tabs.update(tabId, { url: warningUrl });
}

function mapScoreToDecision(score) {
  if (score === undefined || score === null) return 'UNKNOWN';
  if (score >= 70) return 'DANGER';
  if (score >= 40) return 'REVIEW';
  return 'SAFE';
}

function updateBadge(tabId, decision) {
  let text = '';
  let color = '#4CAF50';

  switch (decision) {
    case 'SAFE': text = ''; color = '#4CAF50'; break;
    case 'DANGER': text = '!'; color = '#F44336'; break;
    case 'BLOCK': text = 'X'; color = '#F44336'; break;
    case 'REVIEW': text = '?'; color = '#FF9800'; break;
    default: text = ''; color = '#9E9E9E';
  }

  chrome.action.setBadgeText({ tabId, text });
  chrome.action.setBadgeBackgroundColor({ color });
}

function showDangerNotification(tabId, url, result) {
  if (!settings.protectionEnabled) return;
  const notificationId = `danger_${Date.now()}`;
  chrome.notifications.create(notificationId, {
    type: 'basic',
    iconUrl: '../icons/icon48.png',
    title: 'PhishShield TR - Tehlikeli Site Tespit Edildi',
    message: `${extractDomain(url)} adresi phishing riski iceriyor!\nRisk Skoru: ${result.risk_score || result.score}/100`,
    priority: 2,
    buttons: [{ title: 'Siteyi Kapat' }, { title: 'Yoksay' }]
  });
}

function isHttpUrl(url) {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch { return false; }
}

function extractDomain(url) {
  try {
    const parsed = new URL(url);
    return parsed.hostname;
  } catch { return url; }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.type) {
    case 'GET_ANALYSIS':
      sendResponse({ result: lastAnalysis, url: currentTabUrl });
      break;
    case 'ANALYZE_URL':
      handleTabUpdate(message.tabId || null, message.url);
      sendResponse({ status: 'analyzing' });
      break;
    case 'GET_SETTINGS':
      sendResponse({ settings });
      break;
    case 'UPDATE_SETTINGS':
      settings = { ...settings, ...message.settings };
      chrome.storage.local.set({ phishshield_settings: settings }, () => {
        sendResponse({ status: 'updated', settings });
      });
      return true;
    case 'CLEAR_CACHE':
      phishShieldAPI.clearCache();
      sendResponse({ status: 'cache_cleared' });
      break;
    case 'SEND_FEEDBACK':
      phishShieldAPI.sendFeedback(message.url, message.feedbackType, message.details)
        .then(success => sendResponse({ success }))
        .catch(err => sendResponse({ success: false, error: err.message }));
      return true;
    case 'CLOSE_DANGEROUS_TAB':
      // Aktif sekmeyi kapat veya güvenli sayfaya yönlendir
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs[0]) {
          // Yeni sekme aç (güvenli sayfa)
          chrome.tabs.create({ url: 'https://www.google.com' });
          // Mevcut tehlikeli sekmeyi kapat
          chrome.tabs.remove(tabs[0].id);
        }
      });
      sendResponse({ status: 'closing' });
      return true;
    default:
      sendResponse({ error: 'Unknown message type' });
  }
  return true;
});

setInterval(() => { phishShieldAPI.cleanupCache(); }, 60000);
console.log('PhishShield TR Service Worker baslatildi');
