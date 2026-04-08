let API_BASE = "http://127.0.0.1:8002";
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
  if (!subScores) return;
  const labels = {
    "ml_prediction": "AI (Machine Learning)",
    "rule_base": "Kural Tabanlı Analiz",
    "intel": "Tehdit İstihbaratı"
  };

  subScoreGrid.innerHTML = "";
  Object.entries(subScores).forEach(([key, val]) => {
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
  });
}

function renderFindings(reasons) {
  findingsList.innerHTML = "";
  (reasons || ["Şüpheli özellik bulunamadı."]).forEach(reason => {
    const li = document.createElement("li");
    li.textContent = reason;
    findingsList.appendChild(li);
  });
}

function renderRecommendations(recs) {
  recsList.innerHTML = "";
  (recs || []).forEach(rec => {
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
        const fallback = API_BASE.includes("127.0.0.1") ? "http://localhost:8002" : "http://127.0.0.1:8002";
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
    animateScore(data.score);
    riskBadge.textContent = data.risk_level;
    riskBadge.className = `risk-badge risk-${getRiskClass(data.score)}`;
    threatType.textContent = data.threat_type;
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
    if(currentUrl && currentUrl.startsWith("http")) analyzeUrl(currentUrl);
});
document.addEventListener("DOMContentLoaded", init);
