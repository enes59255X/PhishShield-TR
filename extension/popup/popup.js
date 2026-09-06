/**
 * PhishShield TR - Popup JavaScript
 */

document.addEventListener('DOMContentLoaded', () => {
  initPopup();
});

const states = {
  loading: document.getElementById('loading-state'),
  safe: document.getElementById('safe-state'),
  danger: document.getElementById('danger-state'),
  review: document.getElementById('review-state'),
  unknown: document.getElementById('unknown-state'),
  error: document.getElementById('error-state')
};

let currentUrl = null;
let currentResult = null;

async function initPopup() {
  setupEventListeners();
  loadStats();
  loadSettings();
  await getCurrentTabAnalysis();
}

function loadSettings() {
  // Load from local storage directly for immediate response
  chrome.storage.local.get(['phishshield_settings'], (result) => {
    const settings = result.phishshield_settings || {
      protectionEnabled: true,
      formProtection: true,
      autoScan: true,
      advancedMode: false
    };
    
    document.getElementById('setting-protection').checked = settings.protectionEnabled !== false;
    document.getElementById('setting-form-protection').checked = settings.formProtection !== false;
    document.getElementById('setting-auto-scan').checked = settings.autoScan !== false;
    document.getElementById('setting-advanced-mode').checked = settings.advancedMode === true;
    
    document.getElementById('protection-toggle').checked = settings.protectionEnabled !== false;
  });
  
  // Also sync with service worker
  chrome.runtime.sendMessage({ type: 'GET_SETTINGS' }, (response) => {
    if (response && response.settings) {
      const swSettings = response.settings;
      document.getElementById('setting-protection').checked = swSettings.protectionEnabled !== false;
      document.getElementById('setting-form-protection').checked = swSettings.formProtection !== false;
      document.getElementById('setting-auto-scan').checked = swSettings.autoScan !== false;
      document.getElementById('setting-advanced-mode').checked = swSettings.advancedMode === true;
      
      document.getElementById('protection-toggle').checked = swSettings.protectionEnabled !== false;
    }
  });
}

function setupEventListeners() {
  // Header toggle
  const headerToggle = document.getElementById('protection-toggle');
  headerToggle.addEventListener('change', (e) => {
    const enabled = e.target.checked;
    updateSetting('protectionEnabled', enabled);
    document.getElementById('setting-protection').checked = enabled;
  });

  // Settings link
  document.getElementById('link-settings').addEventListener('click', (e) => {
    e.preventDefault();
    showSettingsModal();
  });

  // Close settings
  document.getElementById('btn-close-settings').addEventListener('click', hideSettingsModal);

  // Settings toggles - with direct DOM listeners
  const settingProtection = document.getElementById('setting-protection');
  settingProtection.addEventListener('change', (e) => {
    const enabled = e.target.checked;
    updateSetting('protectionEnabled', enabled);
    document.getElementById('protection-toggle').checked = enabled;
  });

  document.getElementById('setting-form-protection').addEventListener('change', (e) => {
    updateSetting('formProtection', e.target.checked);
  });

  document.getElementById('setting-auto-scan').addEventListener('change', (e) => {
    updateSetting('autoScan', e.target.checked);
  });

  document.getElementById('setting-advanced-mode').addEventListener('change', (e) => {
    updateSetting('advancedMode', e.target.checked);
  });

  // Block site button - close the dangerous tab with animation and navigate away
  document.getElementById('btn-block-site')?.addEventListener('click', async () => {
    try {
      // Önce popup'ı kapat (animasyon için)
      const popup = document.querySelector('.container');
      if (popup) {
        popup.style.transition = 'all 0.3s ease-out';
        popup.style.opacity = '0';
        popup.style.transform = 'scale(0.9)';
      }

      // Aktif sekmeyi bul ve kapat
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tab && tab.id) {
        // Kısa bir gecikme ile sekmeyi kapat (animasyon için)
        await new Promise(resolve => setTimeout(resolve, 300));

        // Yeni sekme aç ve eski sekmeyi kapat
        await chrome.tabs.create({ url: 'https://www.google.com' });
        await chrome.tabs.remove(tab.id);
      }
    } catch (error) {
      console.error('Failed to close tab:', error);
      // Fallback
      window.close();
    }
  });

  // Retry button
  document.getElementById('btn-retry')?.addEventListener('click', () => {
    getCurrentTabAnalysis();
  });

  // Feedback link
  document.getElementById('link-feedback')?.addEventListener('click', (e) => {
    e.preventDefault();
    showFeedbackModal();
  });

  // Feedback buttons
  document.getElementById('btn-submit-feedback')?.addEventListener('click', () => {
    submitFeedbackFromModal();
  });
  document.getElementById('btn-close-feedback')?.addEventListener('click', hideFeedbackModal);

  document.querySelectorAll('[data-feedback]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      submitFeedback(e.target.dataset.feedback);
    });
  });

  // Modal backdrop click to close
  document.querySelectorAll('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal) {
        modal.classList.add('hidden');
      }
    });
  });
}

function updateSetting(key, value) {
  // Update UI immediately for responsiveness
  if (key === 'protectionEnabled') {
    document.getElementById('protection-toggle').checked = value;
  }
  
  // Send to service worker
  chrome.runtime.sendMessage({ 
    type: 'UPDATE_SETTINGS', 
    settings: { [key]: value } 
  });
  
  // Also save to local storage for persistence
  chrome.storage.local.get(['phishshield_settings'], (result) => {
    const settings = result.phishshield_settings || {};
    settings[key] = value;
    chrome.storage.local.set({ phishshield_settings: settings });
  });
}

async function getCurrentTabAnalysis() {
  showState('loading');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab || !tab.url || !isHttpUrl(tab.url)) {
      showState('unknown');
      return;
    }

    currentUrl = tab.url;

    const response = await chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' });

    if (response.result) {
      currentResult = response.result;
      displayResult(currentResult);
    } else {
      await chrome.runtime.sendMessage({ type: 'ANALYZE_URL', url: currentUrl });

      setTimeout(async () => {
        const newResponse = await chrome.runtime.sendMessage({ type: 'GET_ANALYSIS' });
        if (newResponse.result) {
          currentResult = newResponse.result;
          displayResult(currentResult);
        } else {
          showState('unknown');
        }
      }, 1500);
    }
  } catch (error) {
    console.error('Analysis error:', error);
    showError(error.message);
  }
}

function displayResult(result) {
  if (!result) {
    showState('unknown');
    return;
  }

  const decision = result.decision || mapScoreToDecision(result.score, result.risk_level);
  const riskScore = result.risk_score || result.score || 0;
  const confidence = result.confidence || (decision === 'SAFE' ? 95 : 50);
  const reasons = result.reasons || [];
  const domain = extractDomain(currentUrl);

  if (decision === 'SAFE' || riskScore < 40) {
    showState('safe');
    document.getElementById('safe-domain').textContent = domain;
    document.getElementById('safe-confidence').textContent = `%${confidence}`;
    
    const reasonsEl = document.getElementById('safe-reasons');
    if (reasons.length > 0) {
      reasonsEl.innerHTML = `
        <h4>Neden Guvenli:</h4>
        <ul>${reasons.slice(0, 5).map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      `;
    } else {
      reasonsEl.innerHTML = `
        <h4>Neden Guvenli:</h4>
        <ul><li>Guvenilir platform</li><li>Domain dogrulandi</li></ul>
      `;
    }
  } else if (decision === 'DANGER' || decision === 'BLOCK' || riskScore >= 70) {
    showState('danger');
    document.getElementById('danger-domain').textContent = domain;
    document.getElementById('danger-score').textContent = `%${riskScore}`;
    
    const reasonsEl = document.getElementById('danger-reasons');
    if (reasons.length > 0) {
      reasonsEl.innerHTML = `
        <h4>Tespit Nedenleri:</h4>
        <ul>${reasons.slice(0, 5).map(r => `<li>${escapeHtml(r)}</li>`).join('')}</ul>
      `;
    } else {
      reasonsEl.innerHTML = `
        <h4>Tespit Nedenleri:</h4>
        <ul><li>Phishing site olarak tespit edildi</li></ul>
      `;
    }
  } else if (decision === 'REVIEW' || (riskScore >= 40 && riskScore < 70)) {
    showState('review');
    document.getElementById('review-domain').textContent = domain;
    document.getElementById('review-score').textContent = `%${riskScore}`;
  } else {
    showState('unknown');
  }
}

function mapScoreToDecision(score, riskLevel) {
  if (score === undefined || score === null) {
    if (riskLevel === 'GÜVENLİ' || riskLevel === 'Guvenli') return 'SAFE';
    if (riskLevel === 'KRITIK RISK' || riskLevel === 'Yuksek Risk' || riskLevel === 'KRİTİK RİSK') return 'DANGER';
    if (riskLevel === 'Orta Risk') return 'REVIEW';
    return 'UNKNOWN';
  }
  if (score >= 70) return 'DANGER';
  if (score >= 40) return 'REVIEW';
  return 'SAFE';
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function showState(stateName) {
  Object.values(states).forEach(el => el.classList.add('hidden'));
  if (states[stateName]) {
    states[stateName].classList.remove('hidden');
  }
}

function showError(message) {
  showState('error');
  document.getElementById('error-message').textContent = message || 'Bilinmeyen hata olustu.';
}

function loadStats() {
  chrome.storage.local.get(['phishshield_stats'], (result) => {
    const stats = result.phishshield_stats || { today: 0 };
    document.getElementById('today-count').textContent = stats.today;
  });
}

function showFeedbackModal() {
  if (!currentUrl) return;
  document.getElementById('feedback-url').textContent = `URL: ${extractDomain(currentUrl)}`;
  document.getElementById('feedback-modal').classList.remove('hidden');
}

function hideFeedbackModal() {
  document.getElementById('feedback-modal').classList.add('hidden');
  document.getElementById('feedback-note').value = '';
}

function showSettingsModal() {
  loadSettings();
  document.getElementById('settings-modal').classList.remove('hidden');
}

function hideSettingsModal() {
  document.getElementById('settings-modal').classList.add('hidden');
}

async function submitFeedback(feedbackType) {
  if (!currentUrl) return;

  try {
    await chrome.runtime.sendMessage({
      type: 'SEND_FEEDBACK',
      url: currentUrl,
      feedbackType: feedbackType,
      details: {
        risk_score: currentResult?.risk_score || currentResult?.score,
        decision: currentResult?.decision,
        note: ''
      }
    });
    hideFeedbackModal();
    alert('Geri bildiriminiz icin tesekkurler!');
  } catch (error) {
    console.error('Feedback error:', error);
    alert('Geri bildirim gonderilemedi.');
  }
}

async function submitFeedbackFromModal() {
  if (!currentUrl) return;
  const note = document.getElementById('feedback-note').value;

  try {
    await chrome.runtime.sendMessage({
      type: 'SEND_FEEDBACK',
      url: currentUrl,
      feedbackType: 'manual_feedback',
      details: {
        risk_score: currentResult?.risk_score || currentResult?.score,
        decision: currentResult?.decision,
        note: note
      }
    });
    hideFeedbackModal();
    alert('Geri bildiriminiz icin tesekkurler!');
  } catch (error) {
    console.error('Feedback error:', error);
    alert('Geri bildirim gonderilemedi.');
  }
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
