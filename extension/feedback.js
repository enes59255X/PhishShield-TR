// PhishShield TR - Feedback Script (Kullanıcı Geri Bildirimi)
// Kullanıcıların siteyi güvenli/tehlikeli olarak işaretlemesi

const API_BASE = "http://127.0.0.1:8002";

// Geri bildirim gönder
async function sendFeedback(url, vote) {
  try {
    const res = await fetch(`${API_BASE}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url, vote })
    });
    return res.ok;
  } catch (e) {
    console.log("PhishShield: Feedback gönderilemedi", e);
    return false;
  }
}

// Popup'tan çağrılacak fonksiyon
function initFeedbackListener() {
  const safeBtn = document.getElementById("feedback-safe");
  const unsafeBtn = document.getElementById("feedback-unsafe");
  
  if (safeBtn) {
    safeBtn.addEventListener("click", async () => {
      const url = document.getElementById("currentUrl")?.textContent;
      if (url) {
        const success = await sendFeedback(url, 1);
        if (success) {
          alert("Teşekkürler! Geri bildirimin kaydedildi.");
        }
      }
    });
  }
  
  if (unsafeBtn) {
    unsafeBtn.addEventListener("click", async () => {
      const url = document.getElementById("currentUrl")?.textContent;
      if (url) {
        const success = await sendFeedback(url, -1);
        if (success) {
          alert("Teşekkürler! Geri bildirimin kaydedildi.");
        }
      }
    });
  }
}

// DOM hazırsa çalıştır
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initFeedbackListener);
} else {
  initFeedbackListener();
}