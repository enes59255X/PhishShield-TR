// PhishShield TR - Content Script (Otomatik Gerçek Zamanlı Koruma)
// Sayfa yüklendiğinde otomatik analiz yapar

const API_BASE = "http://127.0.0.1:8002";
const RISK_THRESHOLD = 40;
const HIGH_RISK_THRESHOLD = 60;
const CRITICAL_RISK_THRESHOLD = 80;

// Karalistedeki siteleri kontrol et
function checkAllowlist(url) {
  const allowlist = JSON.parse(localStorage.getItem("phishshield_allowlist") || "{}");
  return allowlist[url] !== undefined;
}

// Karalisteye site ekle
function addToAllowlist(url, isSafe) {
  const allowlist = JSON.parse(localStorage.getItem("phishshield_allowlist") || "{}");
  allowlist[url] = isSafe;
  localStorage.setItem("phishshield_allowlist", JSON.stringify(allowlist));
}

// Sol alt köşesinde bildirim kutusu oluştur
function showBottomRightNotification(score, riskLevel, reasons) {
  // Mevcut bildirim varsa kaldır
  const existing = document.getElementById("phishshield-notification");
  if (existing) existing.remove();
  
  const notification = document.createElement("div");
  notification.id = "phishshield-notification";
  
  // Risk seviyesine göre stil
  let bgColor, icon, urgency;
  if (riskLevel.includes("KRİTİK")) {
    bgColor = "#dc2626";
    icon = "";
    urgency = "KRİTİK RİSK";
  } else if (riskLevel.includes("YÜKSEK")) {
    bgColor = "#ea580c";
    icon = "";
    urgency = "YÜKSEK RİSK";
  } else {
    bgColor = "#ca8a04";
    icon = "";
    urgency = "DİKKAT";
  }
  
  notification.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: ${bgColor};
    color: white;
    padding: 15px 20px;
    border-radius: 10px;
    font-family: Arial, sans-serif;
    font-size: 14px;
    font-weight: bold;
    box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    z-index: 999999;
    max-width: 350px;
    border: 2px solid rgba(255,255,255,0.3);
    animation: slideInRight 0.5s ease-out;
    cursor: pointer;
  `;
  
  notification.innerHTML = `
    <div style="display: flex; align-items: center; gap: 10px;">
      <div style="font-size: 24px;">${icon}</div>
      <div>
        <div style="font-size: 12px; opacity: 0.9;">PhishShield TR</div>
        <div style="font-size: 16px; margin: 2px 0;">${urgency}</div>
        <div style="font-size: 11px; opacity: 0.8;">Puan: ${score}/100</div>
        ${reasons.length > 0 ? `<div style="font-size: 10px; opacity: 0.7; margin-top: 3px;">${reasons[0]}</div>` : ''}
      </div>
    </div>
    <div style="font-size: 10px; margin-top: 8px; opacity: 0.8;">Tikla detaylar...</div>
  `;
  
  // CSS animasyonu ekle
  if (!document.getElementById("phishshield-styles")) {
    const style = document.createElement("style");
    style.id = "phishshield-styles";
    style.textContent = `
      @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);
  }
  
  // Tıklanınca detaylı uyarı göster
  notification.addEventListener("click", () => {
    showWarning(score, riskLevel, reasons);
    notification.remove();
  });
  
  // Otomatik kapanma (10 saniye)
  setTimeout(() => {
    if (notification.parentNode) {
      notification.style.animation = "slideInRight 0.5s ease-out reverse";
      setTimeout(() => notification.remove(), 500);
    }
  }, 10000);
  
  document.body.appendChild(notification);
}

// Uyarı banner'ı oluştur
function showWarning(score, riskLevel, reasons) {
  const banner = document.createElement("div");
  banner.id = "phishshield-warning";
  
  // Risk seviyesine göre görsel stil
  let bgColor, icon, urgency;
  if (riskLevel.includes("KRİTİK")) {
    bgColor = "#dc2626";
    icon = "";
    urgency = "KRİTİK TEHLİKE!";
  } else if (riskLevel.includes("YÜKSEK")) {
    bgColor = "#ea580c";
    icon = "";
    urgency = "YÜKSEK RİSK!";
  } else {
    bgColor = "#eab308";
    icon = "";
    urgency = "DİKKAT!";
  }
  
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
    background: ${bgColor}; color: white; padding: 15px 20px; 
    font-family: system-ui, sans-serif; font-size: 14px; 
    box-shadow: 0 4px 20px rgba(0,0,0,0.4); display: flex;
    align-items: center; justify-content: space-between; gap: 20px;
    border-bottom: 3px solid rgba(255,255,255,0.3);
  `;
  
  const message = document.createElement("div");
  message.style.flex = "1";
  message.innerHTML = `
    <div style="font-weight: bold; font-size: 16px; margin-bottom: 5px;">
      ${icon} PhishShield TR: ${urgency}
    </div>
    <div>Risk Seviyesi: ${riskLevel} (Skor: ${score}/100)</div>
    <div style="margin-top: 5px; font-size: 12px; opacity: 0.9;">
      ${reasons[0] || "Şüpheli site tespit edildi"}
    </div>
  `;
  
  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "10px";
  actions.style.alignItems = "center";
  
  // Yüksek/Kritik risk için ek uyarı butonu
  if (score >= HIGH_RISK_THRESHOLD) {
    const alertBtn = document.createElement("button");
    alertBtn.textContent = "🔔 Bildir";
    alertBtn.style.cssText = "background: #ef4444; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; color: white; font-weight: 600;";
    alertBtn.onclick = () => {
      // Siteyi bildir
      chrome.runtime.sendMessage({
        action: "reportSite", 
        url: window.location.href,
        score: score,
        riskLevel: riskLevel
      });
      alertBtn.textContent = "✓ Bildirildi";
      alertBtn.disabled = true;
    };
    actions.appendChild(alertBtn);
  }
  
  const safeBtn = document.createElement("button");
  safeBtn.textContent = "✓ Güvenli";
  safeBtn.style.cssText = "background: #22c55e; border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; color: white; font-weight: 600;";
  safeBtn.onclick = () => {
    addToAllowlist(window.location.href, true);
    banner.remove();
  };
  
  const closeBtn = document.createElement("button");
  closeBtn.textContent = "✕ Kapat";
  closeBtn.style.cssText = "background: rgba(0,0,0,0.3); border: none; padding: 8px 15px; border-radius: 4px; cursor: pointer; color: white;";
  closeBtn.onclick = () => banner.remove();
  
  actions.appendChild(safeBtn);
  actions.appendChild(closeBtn);
  banner.appendChild(message);
  banner.appendChild(actions);
  
  document.body.prepend(banner);
  
  // Kritik risk için ek önlemler
  if (score >= CRITICAL_RISK_THRESHOLD) {
    // Sayfayı karart
    const overlay = document.createElement("div");
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.8); z-index: 999998;
      display: flex; align-items: center; justify-content: center;
      color: white; font-family: system-ui, sans-serif;
    `;
    overlay.innerHTML = `
      <div style="text-align: center; padding: 40px;">
        <h1 style="color: #dc2626; font-size: 48px; margin-bottom: 20px;">🚨 KRİTİK TEHLİKE 🚨</h1>
        <p style="font-size: 24px; margin-bottom: 30px;">Bu site çok tehlikeli olabilir!</p>
        <p style="font-size: 18px; margin-bottom: 30px;">Skor: ${score}/100 - ${riskLevel}</p>
        <button onclick="this.parentElement.parentElement.remove()" style="
          background: #dc2626; color: white; border: none; padding: 15px 30px; 
          border-radius: 8px; font-size: 18px; cursor: pointer; font-weight: bold;
        ">Riski Kabul Et ve Devam Et</button>
      </div>
    `;
    document.body.appendChild(overlay);
  }
}

// Siteyi analiz et - OTOMATİK
async function analyzeCurrentSite() {
  const url = window.location.href;
  console.log("PhishShield TR: Auto-analyzing", url);
  
  // Karalisteye alınmış mı kontrol et
  if (checkAllowlist(url)) {
    console.log("PhishShield TR: URL is in allowlist, skipping analysis");
    return;
  }
  
  // URL geçerli mi kontrol et
  if (!url.startsWith('http')) {
    console.log("PhishShield TR: Invalid URL, skipping");
    return;
  }
  
  try {
    console.log(`PhishShield TR: Connecting to ${API_BASE}/analyze`);
    
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });
    
    console.log(`PhishShield TR: Response status: ${res.status}`);
    if (!res.ok) {
      console.log(`PhishShield TR: Response not ok: ${res.status}`);
      return;
    }
    
    const data = await res.json();
    
    console.log("PhishShield TR: Analysis result", {
      url: url,
      score: data.score,
      riskLevel: data.risk_level
    });
    
    // Risk seviyesine göre otomatik uyarý göster
    if (data.score >= RISK_THRESHOLD) {
      console.log("PhishShield TR: Risk detected, showing warnings");
      
      // Riskli site - önce sol alt bildirim göster
      if (data.score >= HIGH_RISK_THRESHOLD) {
        showBottomRightNotification(data.score, data.risk_level, data.reasons);
      }
      
      // Riskli site - uyarý göster
      showWarning(data.score, data.risk_level, data.reasons);
      
      // Eklentiye bilgi gönder
      chrome.runtime.sendMessage({
        type: "siteAnalysis",
        action: "highRiskAlert",
        data: {
          url: url,
          score: data.score,
          riskLevel: data.risk_level,
          reasons: data.reasons
        }
      }).catch(err => console.log("Runtime message error:", err));
    } else {
      console.log("PhishShield TR: Site is safe");
    }
  } catch (e) {
    console.log("PhishShield TR: Backend unavailable, using offline analysis");
    performOfflineAnalysis(url);
  }
}

// Offline analiz yap
function performOfflineAnalysis(url) {
  console.log("PhishShield TR: Performing offline analysis for", url);
  
  // Basit phishing tespiti
  const phishingIndicators = [
    'tebleherseyhazir.click',
    'toblahorseyhazir.click',
    'cepteteb-login.click',
    'eba-giris.click',
    'e-devlet-login.click',
    '.click',
    '.xyz',
    '.top',
    'login',
    'giris',
    'secure',
    'verification'
  ];
  
  const safeIndicators = [
    'turkiye.gov.tr',
    'e-devlet.gov.tr',
    'edevlet.gov.tr',
    'usom.gov.tr',
    'cimer.gov.tr',
    'gib.gov.tr',
    'sgk.gov.tr',
    'tcmb.gov.tr',
    'btk.gov.tr',
    'meb.gov.tr',
    'milliegitim.gov.tr',
    'yok.gov.tr',
    'osym.gov.tr',
    'nvi.gov.tr',
    'eba.gov.tr',
    'ogmm.gov.tr',
    '.gov.tr'
  ];
  
  const urlLower = url.toLowerCase();
  let score = 20; // Default güvenli skor
  let riskLevel = "DUSUK RISK";
  let isPhishing = false;
  
  // Safe kontrolü
  for (const safe of safeIndicators) {
    if (urlLower.includes(safe)) {
      score = 0;
      riskLevel = "GUVENLI";
      isPhishing = false;
      break;
    }
  }
  
  // Phishing kontrolü
  if (score > 0) {
    for (const indicator of phishingIndicators) {
      if (urlLower.includes(indicator)) {
        score = 85;
        riskLevel = "KRITIK RISK";
        isPhishing = true;
        break;
      }
    }
  }
  
  console.log("PhishShield TR: Offline analysis result", {
    url: url,
    score: score,
    riskLevel: riskLevel,
    isPhishing: isPhishing
  });
  
  // Uyarý göster
  if (score >= RISK_THRESHOLD) {
    if (score >= HIGH_RISK_THRESHOLD) {
      showBottomRightNotification(score, riskLevel, ["Offline analizi"]);
    }
    showWarning(score, riskLevel, ["Offline analizi"]);
  }
}

// Sayfa yüklendiğinde analiz et - DAHA HIZLI
console.log("PhishShield TR: Content script loaded for", window.location.href);

// HIZLI analiz - bekleme yok
if (document.readyState === "loading") {
  // Sayfa henüz yükleniyor - DOM ready'de baþla
  document.addEventListener("DOMContentLoaded", () => {
    console.log("PhishShield TR: DOM ready, analyzing immediately");
    analyzeCurrentSite(); // Hemen analiz et
  });
} else {
  // Sayfa zaten yüklendi - hemen baþla
  console.log("PhishShield TR: Document ready, analyzing now");
  analyzeCurrentSite(); // Hemen analiz et
}

// URL deðiþtiðinde tekrar analiz et (SPA'lar için)
let lastUrl = location.href;
new MutationObserver(() => {
  if (location.href !== lastUrl) {
    lastUrl = location.href;
    analyzeCurrentSite();
  }
}).observe(document.body, { childList: true, subtree: true });