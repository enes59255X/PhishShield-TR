let API_BASE = "http://127.0.0.1:8004";
console.log("PhishShield Popup Loaded");

const stateLoading = document.getElementById("stateLoading");
const stateError = document.getElementById("stateError");
const stateResult = document.getElementById("stateResult");
const currentUrlEl = document.getElementById("currentUrl");
const loadingTextEl = document.getElementById("loadingText");
const errorMsgEl = document.getElementById("errorMsg");
const btnReanalyze = document.getElementById("btnReanalyze");

const scoreNumber = document.getElementById("scoreNumber");
const scoreFill = document.getElementById("scoreFill");
const riskBadge = document.getElementById("riskBadge");
const threatType = document.getElementById("threatType");
const subScoreGrid = document.getElementById("subScoreGrid");
const findingsList = document.getElementById("findingsList");
const recsList = document.getElementById("recsList");

let currentUrl = "";

function showState(state) {
  stateLoading.classList.add("hidden");
  stateError.classList.add("hidden");
  stateResult.classList.add("hidden");
  state.classList.remove("hidden");
}

function setUrl(url) {
  currentUrl = url;
  currentUrlEl.textContent = url;
  currentUrlEl.title = url;
}

function getRiskClass(score) {
  if (score >= 80) return "critical";
  if (score >= 50) return "high";
  if (score >= 20) return "medium";
  return "low";
}

function getBarColor(score) {
  if (score <= 19) return "#22c55e"; // Green
  if (score <= 49) return "#f59e0b"; // Orange
  if (score <= 79) return "#f97316"; // Dark Orange
  return "#ef4444"; // Red
}

function animateScore(score) {
  console.log("Animating score:", score); // Debug log
  
  const circumference = 314;
  const offset = circumference - (score / 100) * circumference;
  const color = getBarColor(score);

  scoreFill.style.stroke = color;
  scoreFill.style.strokeDashoffset = offset;
  scoreNumber.style.color = color;

  let current = 0;
  scoreNumber.textContent = "0";
  const duration = 600;
  const step = score / (duration / 16);
  const timer = setInterval(() => {
    current = Math.min(current + step, score);
    scoreNumber.textContent = Math.floor(current);
    if (current >= score) clearInterval(timer);
  }, 16);
}

function renderSubScores(subScores) {
  console.log("renderSubScores called with:", subScores);
  
  if (!subScores) {
    console.log("subScores is empty or null");
    subScoreGrid.innerHTML = '<div style="color: var(--text-muted); font-size: 12px; text-align: center; padding: 20px;">Analiz verisi alınamadı</div>';
    return;
  }
  
  const labels = {
    "ml_prediction": "AI Tahmini",
    "rule_base": "Kural Tabanlı",
    "intel": "Tehdit İstihbaratı",
    "url_domain_analizi": "URL/Domain",
    "form_analizi": "Form Analizi",
    "icerik_analizi": "İçerik",
    "davranis_analizi": "Davranış",
    "js_obfuscation": "JS Şifreleme",
    "external_scripts": "Harici Scriptler",
    "ssl_cert": "SSL Sertifika",
    "screenshot_logo": "Ekran Görüntüsü"
  };

  subScoreGrid.innerHTML = "";
  let hasValidScores = false;
  
  Object.entries(subScores).forEach(([key, val]) => {
    // Sadece değeri > 0 olan ve sayısal olanları göster
    if (typeof val === 'number' && val > 0) {
      hasValidScores = true;
      const label = labels[key] || key;
      const color = getBarColor(val);
      const item = document.createElement("div");
      item.className = "sub-score-item";
      item.innerHTML = `
        <div class="sub-score-name">${label}</div>
        <div class="sub-score-bar-wrap">
          <div class="sub-score-bar" style="width: ${val}%; background: ${color}"></div>
        </div>
        <div class="sub-score-val">${val}/100</div>
      `;
      subScoreGrid.appendChild(item);
    }
  });
  
  // Hiçbir değer yoksa mesaj göster
  if (!hasValidScores) {
    subScoreGrid.innerHTML = '<div style="color: var(--text-muted); font-size: 11px; text-align: center; padding: 12px; grid-column: 1 / -1;">Risk tespit edilmedi</div>';
  }
}

function renderFindings(reasons) {
  findingsList.innerHTML = "";
  if (!reasons || reasons.length === 0) {
    findingsList.innerHTML = '<li style="color: var(--text-muted);">Belirgin bir bulgu tespit edilmedi</li>';
    return;
  }
  
  reasons.forEach(reason => {
    const li = document.createElement("li");
    // Emoji ve özel karakterleri koru
    li.textContent = reason;
    
    // Risk seviyesine göre stil uygula
    if (reason.includes("🚨") || reason.includes("KRİTİK") || reason.includes("TEHLİKELİ")) {
      li.style.borderLeft = "3px solid var(--risk-critical)";
      li.style.background = "var(--risk-critical-bg)";
    } else if (reason.includes("⚠")) {
      li.style.borderLeft = "3px solid var(--risk-high)";
      li.style.background = "var(--risk-high-bg)";
    } else if (reason.includes("✓") || reason.includes("✅") || reason.includes("GÜVENLİ")) {
      li.style.borderLeft = "3px solid var(--risk-low)";
      li.style.background = "var(--risk-low-bg)";
    }
    
    findingsList.appendChild(li);
  });
}

function renderRecommendations(recs) {
  recsList.innerHTML = "";
  if (!recs || recs.length === 0) {
    recsList.innerHTML = '<li style="color: var(--text-muted);">Özel bir öneri bulunmuyor</li>';
    return;
  }
  
  recs.forEach(rec => {
    const li = document.createElement("li");
    li.textContent = rec;
    recsList.appendChild(li);
  });
}

async function analyzeUrl(url) {
  showState(stateLoading);
  try {
    // 1. Health check with fallback
    let health = await fetch(`${API_BASE}/health`).catch(() => null);
    
    if (!health || !health.ok) {
        // Try fallback to localhost if 127.0.0.1 failed
        const fallback = API_BASE.includes("127.0.0.1") ? "http://localhost:8004" : "http://127.0.0.1:8004";
        console.log("Trying fallback:", fallback);
        health = await fetch(`${fallback}/health`).catch(() => null);
        if (health && health.ok) {
            API_BASE = fallback;
        } else {
            throw new Error("Backend servisine ulaşılamıyor. Lütfen uvicorn/python app.py'nin çalıştığından emin olun.");
        }
    }

    // 2. Analyze
    const res = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url })
    });

    if (!res.ok) {
        const err = await res.json().catch(() => ({ detail: "Bilinmeyen hata" }));
        throw new Error(err.detail);
    }
    
    const data = await res.json();
    
    showState(stateResult);
    animateScore(data.score || 0);
    
    // Risk badge güncelle
    const riskLevel = data.risk_level || (data.score >= 80 ? "KRİTİK RİSK" : data.score >= 50 ? "YÜKSEK RİSK" : data.score >= 20 ? "ORTA RİSK" : "DÜŞÜK RİSK");
    riskBadge.textContent = riskLevel;
    riskBadge.className = `risk-badge risk-${getRiskClass(data.score || 0)}`;
    
    // Tehdit tipi - skora göre özelleştir
    let threatDisplay = data.threat_type;
    if (!threatDisplay) {
        if (data.score === 0) threatDisplay = "✓ Güvenli Site";
        else if (data.score <= 9) threatDisplay = "✓ Normal Site";
        else if (data.score <= 24) threatDisplay = "⚠ Dikkat Edilmesi Gereken Site";
        else threatDisplay = "⚠ Şüpheli Site";
    }
    // Eğer threat_type "Normal Site" veya "SSL Uyarısı" içeriyorsa güvenli göster
    if (threatDisplay.includes("Normal") || threatDisplay.includes("Güvenli") || threatDisplay.includes("SSL")) {
        threatType.style.color = "var(--risk-low)";
    } else if (data.score <= 9) {
        threatType.style.color = "var(--text-secondary)";
    }
    threatType.textContent = threatDisplay;
    
    renderSubScores(data.sub_scores);
    renderFindings(data.reasons);
    renderRecommendations(data.recommendations);

  } catch (e) {
    showState(stateError);
    errorMsgEl.innerHTML = `${e.message}<br><button id="btnOpenDashboard" style="margin-top:10px; background:#3b82f6; color:white; padding:5px 10px; border-radius:5px; cursor:pointer;">Dashboard'a Git</button>`;
    const btn = document.getElementById("btnOpenDashboard");
    if(btn) btn.onclick = () => chrome.tabs.create({ url: `${API_BASE}/dashboard` });
  }
}

async function init() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      const url = tabs[0].url;
      if (url.startsWith("http")) {
        setUrl(url);
        analyzeUrl(url);
      } else {
        setUrl("Tarayıcı Sayfası");
        showState(stateError);
        document.getElementById("errorTitle").textContent = "Sistem Sayfası";
        errorMsgEl.textContent = "Bu sayfa (chrome/ayarlar) analiz edilemez. Lütfen bir web sitesine gidin.";
      }
    }
  });
}

btnReanalyze.addEventListener("click", () => {
    if(currentUrl && currentUrl.startsWith("http")) {
        btnReanalyze.classList.add("spinning");
        analyzeUrl(currentUrl).then(() => {
            setTimeout(() => btnReanalyze.classList.remove("spinning"), 500);
        });
    }
});
document.addEventListener("DOMContentLoaded", init);
