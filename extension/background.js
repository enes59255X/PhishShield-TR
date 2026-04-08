// PhishShield TR - Background Script
// Tab değişikliklerini dinler ve analiz tetikler

const API_BASE = "http://127.0.0.1:8002";
let scannedUrls = new Set();
let highRiskAlerts = new Set();

// Tab güncellemelerini dinle
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    const url = new URL(tab.url).href;
    
    // Oturum için basit deduplikasyon
    if (scannedUrls.has(url)) return;
    scannedUrls.add(url);

    autoAnalyze(url, tabId);
  }
});

// Content script'ten mesajları dinle
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'highRiskAlert') {
    handleHighRiskAlert(message, sender.tab.id);
  } else if (message.action === 'reportSite') {
    handleSiteReport(message);
  }
});

// Yüksek risk uyarılarını yönet
function handleHighRiskAlert(message, tabId) {
  const alertKey = `${message.url}_${message.score}`;
  
  // Yinelenen uyarıları önle
  if (highRiskAlerts.has(alertKey)) return;
  highRiskAlerts.add(alertKey);
  
  // Sistem bildirimi göster
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: ' YÜKSEK RİSK TESPİT EDİLDİ!',
    message: `${message.riskLevel}: ${message.url.substring(0, 50)}...\nSkor: ${message.score}/100`,
    priority: 2,
    requireInteraction: true
  });
  
  // Log kaydet
  console.log('PhishShield High Risk Alert:', {
    url: message.url,
    score: message.score,
    riskLevel: message.riskLevel,
    reasons: message.reasons
  });
}

// Site bildirimini yönet
function handleSiteReport(message) {
  console.log('PhishShield Site Report:', {
    url: message.url,
    score: message.score,
    riskLevel: message.riskLevel
  });
}

// Otomatik analiz fonksiyonu
function autoAnalyze(url, tabId) {
  // Content script'e analiz isteği gönder
  chrome.tabs.sendMessage(tabId, {
    action: 'analyzeSite',
    url: url
  }, (response) => {
    if (chrome.runtime.lastError) {
      console.log('PhishShield Background analysis error:', chrome.runtime.lastError);
    }
  });
  
  // Show confirmation
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '✓ Site Bildirildi',
    message: 'Şüpheli site başarıyla bildirildi. Teşekkürler!',
    priority: 1
  });
}

async function autoAnalyze(url, tabId) {
  // Backend'e erisim denemesi yapma, sadece content script'e bildir
  console.log('Background: Skipping backend analysis, delegating to content script');
}
