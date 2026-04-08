const API_BASE = "http://127.0.0.1:8002";
let scannedUrls = new Set();
let highRiskAlerts = new Set();

// Listen for tab updates
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
    const url = new URL(tab.url).href;
    
    // Simple deduplication for current session
    if (scannedUrls.has(url)) return;
    scannedUrls.add(url);

    autoAnalyze(url, tabId);
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'highRiskAlert') {
    handleHighRiskAlert(message, sender.tab.id);
  } else if (message.action === 'reportSite') {
    handleSiteReport(message);
  }
});

// Handle high-risk alerts
function handleHighRiskAlert(message, tabId) {
  const alertKey = `${message.url}_${message.score}`;
  
  // Prevent duplicate alerts
  if (highRiskAlerts.has(alertKey)) return;
  highRiskAlerts.add(alertKey);
  
  // Show system notification
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/icon128.png',
    title: '🚨 YÜKSEK RİKLİ SİNE TESPİT EDİLDİ!',
    message: `${message.riskLevel}: ${message.url.substring(0, 50)}...\nSkor: ${message.score}/100`,
    priority: 2,
    requireInteraction: true
  });
  
  // Log the alert
  console.log('PhishShield High Risk Alert:', {
    url: message.url,
    score: message.score,
    riskLevel: message.riskLevel,
    reasons: message.reasons,
    timestamp: new Date().toISOString()
  });
}

// Handle site reports
function handleSiteReport(message) {
  // Store report for future analysis
  const report = {
    url: message.url,
    score: message.score,
    riskLevel: message.riskLevel,
    timestamp: new Date().toISOString()
  };
  
  // Get existing reports
  chrome.storage.local.get(['siteReports'], (result) => {
    const reports = result.siteReports || [];
    reports.push(report);
    
    // Keep only last 100 reports
    if (reports.length > 100) {
      reports.splice(0, reports.length - 100);
    }
    
    chrome.storage.local.set({ siteReports: reports });
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
