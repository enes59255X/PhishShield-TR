/**
 * PhishShield TR - Content Script: Detector
 * Sayfa analiz ve koruma
 */

(function() {
  'use strict';

  // Config
  const CONFIG = {
    overlayColor: 'rgba(244, 67, 54, 0.95)',
    warningColor: 'rgba(255, 152, 0, 0.95)',
    infoColor: 'rgba(33, 150, 243, 0.95)',
    position: 'fixed',
    zIndex: 2147483647,
    animationDuration: '0.3s'
  };

  // State
  let currentResult = null;
  let overlayElement = null;
  let settings = {
    protectionEnabled: true,
    showWarnings: true
  };

  /**
   * PhishShield sonucunu isaretle
   */
  function markPage(result) {
    currentResult = result;

    if (!settings.protectionEnabled) return;

    // Body'ye gore stil ekle
    addPageStyles();

    // Sonuca gore isaretle
    switch (result.decision) {
      case 'DANGER':
      case 'BLOCK':
        showDangerOverlay(result);
        break;
      case 'REVIEW':
        showWarningOverlay(result);
        break;
      case 'SAFE':
        showSafeIndicator(result);
        break;
    }
  }

  /**
   * Tehlikeli site overlay'i goster
   */
  function showDangerOverlay(result) {
    removeOverlay();

    overlayElement = document.createElement('div');
    overlayElement.id = 'phishshield-danger-overlay';
    overlayElement.innerHTML = `
      <div class="phishshield-overlay-content">
        <div class="phishshield-icon">🛡️</div>
        <h1>⚠️ TEHLİKELİ SİTE TESPİT EDİLDİ</h1>
        <p class="phishshield-domain">${window.location.hostname}</p>
        <div class="phishshield-score">
          <span class="label">Risk Skoru</span>
          <span class="value">${result.risk_score}/100</span>
        </div>
        <div class="phishshield-reasons">
          <h3>Tespit Nedenleri:</h3>
          <ul>
            ${formatReasons(result)}
          </ul>
        </div>
        <div class="phishshield-actions">
          <button id="phishshield-leave" class="btn-danger">
            Bu Siteyi Terk Et
          </button>
          <button id="phishshield-continue" class="btn-secondary">
            Riski Onaylayip Devam Et
          </button>
        </div>
        <p class="phishshield-info">
          PhishShield TR tarafindan korunuyorsunuz
        </p>
      </div>
    `;

    applyOverlayStyles(overlayElement);
    document.body.appendChild(overlayElement);

    // Event listeners
    document.getElementById('phishshield-leave').addEventListener('click', () => {
      window.location.href = 'about:blank';
    });

    document.getElementById('phishshield-continue').addEventListener('click', () => {
      removeOverlay();
      // Siteyi visited olarak isaretle
      localStorage.setItem('phishshield_accepted_' + window.location.hostname, Date.now().toString());
    });
  }

  /**
   * Uyarı overlay'i goster
   */
  function showWarningOverlay(result) {
    if (!settings.showWarnings) return;

    removeOverlay();

    overlayElement = document.createElement('div');
    overlayElement.id = 'phishshield-warning-overlay';
    overlayElement.innerHTML = `
      <div class="phishshield-warning-content">
        <div class="phishshield-icon">⚠️</div>
        <h2>Şüpheli Site Uyarısı</h2>
        <p>Bu site riskli olabilir: <strong>${window.location.hostname}</strong></p>
        <div class="phishshield-details">
          <span>Risk: ${result.risk_score}/100</span>
          <span>Güven: ${result.confidence || 0}%</span>
        </div>
        <div class="phishshield-actions">
          <button id="phishshield-warn-continue" class="btn-primary">
            Devam Et
          </button>
          <button id="phishshield-warn-close" class="btn-secondary">
            Kapat
          </button>
        </div>
      </div>
    `;

    applyOverlayStyles(overlayElement, CONFIG.warningColor);
    document.body.appendChild(overlayElement);

    document.getElementById('phishshield-warn-continue').addEventListener('click', () => {
      removeOverlay();
    });

    document.getElementById('phishshield-warn-close').addEventListener('click', () => {
      window.history.back();
    });
  }

  /**
   * Guvenli gösterge ekle
   */
  function showSafeIndicator(result) {
    const indicator = document.createElement('div');
    indicator.id = 'phishshield-safe-indicator';
    indicator.innerHTML = `
      <span class="phishshield-badge">🛡️ PhishShield: Güvenli</span>
    `;
    indicator.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: #4CAF50;
      color: white;
      padding: 8px 16px;
      border-radius: 20px;
      font-size: 12px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      z-index: 2147483646;
      box-shadow: 0 2px 10px rgba(0,0,0,0.2);
      opacity: 0;
      transition: opacity 0.3s;
    `;

    document.body.appendChild(indicator);

    setTimeout(() => {
      indicator.style.opacity = '1';
    }, 100);

    setTimeout(() => {
      indicator.style.opacity = '0';
      setTimeout(() => indicator.remove(), 300);
    }, 5000);
  }

  /**
   * Overlay stillerini uygula
   */
  function applyOverlayStyles(element, bgColor = CONFIG.overlayColor) {
    element.style.cssText = `
      position: ${CONFIG.position};
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: ${bgColor};
      z-index: ${CONFIG.zIndex};
      display: flex;
      align-items: center;
      justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      animation: phishshield-fadein ${CONFIG.animationDuration};
    `;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes phishshield-fadein {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .phishshield-overlay-content {
        text-align: center;
        color: white;
        max-width: 500px;
        padding: 40px;
      }
      .phishshield-overlay-content h1 {
        font-size: 28px;
        margin: 20px 0;
        color: white;
      }
      .phishshield-overlay-content .phishshield-icon {
        font-size: 64px;
      }
      .phishshield-domain {
        font-size: 20px;
        opacity: 0.9;
        word-break: break-all;
      }
      .phishshield-score {
        background: rgba(255,255,255,0.2);
        border-radius: 12px;
        padding: 15px 30px;
        margin: 20px 0;
        display: inline-block;
      }
      .phishshield-score .label {
        display: block;
        font-size: 14px;
        opacity: 0.8;
      }
      .phishshield-score .value {
        font-size: 36px;
        font-weight: bold;
      }
      .phishshield-reasons {
        text-align: left;
        background: rgba(0,0,0,0.2);
        border-radius: 12px;
        padding: 20px;
        margin: 20px 0;
      }
      .phishshield-reasons h3 {
        margin: 0 0 10px 0;
        font-size: 16px;
      }
      .phishshield-reasons ul {
        margin: 0;
        padding-left: 20px;
      }
      .phishshield-reasons li {
        margin: 5px 0;
      }
      .phishshield-actions {
        margin-top: 30px;
        display: flex;
        gap: 15px;
        justify-content: center;
        flex-wrap: wrap;
      }
      .phishshield-actions button {
        padding: 12px 30px;
        border-radius: 8px;
        border: none;
        font-size: 16px;
        cursor: pointer;
        transition: transform 0.2s, opacity 0.2s;
      }
      .phishshield-actions button:hover {
        transform: scale(1.05);
      }
      .btn-danger {
        background: #F44336;
        color: white;
      }
      .btn-primary {
        background: #2196F3;
        color: white;
      }
      .btn-secondary {
        background: rgba(255,255,255,0.2);
        color: white;
      }
      .phishshield-info {
        margin-top: 30px;
        font-size: 12px;
        opacity: 0.6;
      }
      .phishshield-warning-content {
        text-align: center;
        color: white;
        max-width: 400px;
        padding: 30px;
      }
      .phishshield-warning-content h2 {
        font-size: 24px;
        margin: 15px 0;
      }
      .phishshield-details {
        display: flex;
        gap: 20px;
        justify-content: center;
        margin: 15px 0;
        font-size: 14px;
        opacity: 0.9;
      }
    `;

    document.head.appendChild(style);
  }

  /**
   * Nedenleri formatla
   */
  function formatReasons(result) {
    if (!result.reasons || !result.reasons.length) {
      return '<li>Tehlikeli site olarak tespit edildi</li>';
    }

    return result.reasons.map(r => `<li>✓ ${r}</li>`).join('');
  }

  /**
   * Overlay'i kaldir
   */
  function removeOverlay() {
    if (overlayElement && overlayElement.parentNode) {
      overlayElement.parentNode.removeChild(overlayElement);
      overlayElement = null;
    }
  }

  /**
   * Sayfa stillerini ekle
   */
  function addPageStyles() {
    if (document.getElementById('phishshield-styles')) return;

    const style = document.createElement('style');
    style.id = 'phishshield-styles';
    style.textContent = `
      .phishshield-processed {
        pointer-events: none;
      }
      .phishshield-processed * {
        pointer-events: auto;
      }
    `;
    document.head.appendChild(style);
  }

  // Message listener
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'PAGE_ANALYSIS_RESULT') {
      markPage(message.result);
      sendResponse({ received: true });
    }
    return true;
  });

  // Initialize
  console.log('PhishShield Detector loaded on:', window.location.hostname);
})();
