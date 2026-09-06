/**
 * PhishShield TR - Content Script: Form Guard
 * Form koruma ve sifre guvenligi
 */

(function() {
  'use strict';

  // Config
  const GUARD_CONFIG = {
    dangerColor: '#F44336',
    warningColor: '#FF9800',
    safeColor: '#4CAF50',
    checkDelay: 500
  };

  // State
  let protectedForms = new Set();
  let settings = {
    formProtection: true,
    showWarnings: true
  };

  /**
   * Form'lari tara ve koru
   */
  function scanAndProtectForms() {
    if (!settings.formProtection) return;

    const forms = document.querySelectorAll('form');
    forms.forEach(form => protectForm(form));
  }

  /**
   * Form'u koruma altina al
   */
  function protectForm(form) {
    if (protectedForms.has(form)) return;
    protectedForms.add(form);

    const formData = analyzeFormElement(form);
    const domain = window.location.hostname;

    // Form bilgilerini logla
    console.log('PhishShield: Form analiz ediliyor', {
      domain,
      action: form.action,
      method: form.method,
      inputs: formData.inputs.length,
      passwordFields: formData.passwordFields
    });

    // Analiz et
    analyzeForm(form, formData, domain);
  }

  /**
   * Form elementini analiz et
   */
  function analyzeFormElement(form) {
    const inputs = Array.from(form.querySelectorAll('input'));
    const passwordFields = inputs.filter(i => i.type === 'password');
    const textFields = inputs.filter(i => i.type === 'text' || i.type === 'email');
    const hiddenFields = inputs.filter(i => i.type === 'hidden');

    return {
      action: form.action || '',
      method: form.method || 'get',
      inputs: inputs.map(i => ({
        type: i.type,
        name: i.name,
        id: i.id,
        placeholder: i.placeholder
      })),
      passwordFields: passwordFields.length,
      textFields: textFields.length,
      hiddenFields: hiddenFields.length,
      hasSubmit: form.querySelector('button[type="submit"], input[type="submit"]') !== null
    };
  }

  /**
   * Form'u analiz et ve sonuca gore islem yap
   */
  function analyzeForm(form, formData, domain) {
    // Form bilgilerini backend'e gonder
    analyzeWithBackend(form, formData, domain)
      .then(result => {
        // Sadece HIGH risk için tam uyarı göster
        // MEDIUM risk için sadece küçük toast göster
        if (result.risk_level === 'HIGH' || result.risk_level === 'CRITICAL') {
          showFormWarning(form, result);
        } else if (result.risk_level === 'MEDIUM') {
          showFormCaution(form, result);
        }
      })
      .catch(error => {
        console.error('PhishShield Form Analysis Error:', error);
      });
  }

  /**
   * Backend'e form analizi icin istek at
   */
  async function analyzeWithBackend(form, formData, domain) {
    try {
      const response = await fetch('http://127.0.0.1:8004/analyze-form', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: window.location.href,
          domain: domain,
          form_action: formData.action,
          form_method: formData.method,
          has_password_field: formData.passwordFields > 0,
          has_hidden_fields: formData.hiddenFields > 0,
          input_count: formData.inputs.length
        }),
      });

      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }

      return await response.json();
    } catch (error) {
      console.error('Form analysis failed:', error);
      // Fallback - local analysis
      return localFormAnalysis(formData, domain);
    }
  }

  /**
   * Local form analizi (fallback)
   */
  function localFormAnalysis(formData, domain) {
    const risks = [];

    // External submit kontrolu
    let hasExternalSubmit = false;
    try {
      const actionUrl = new URL(formData.action, window.location.href);
      if (actionUrl.hostname !== domain) {
        hasExternalSubmit = true;
        risks.push({
          type: 'external_submit',
          message: `Form verisi ${actionUrl.hostname} adresine gonderiliyor`
        });
      }
    } catch {
      // Gecersiz URL
    }

    // Hidden field kontrolu - sadece external submit veya password field ile birlikte tehlikeli
    if (formData.hiddenFields > 0 && (hasExternalSubmit || formData.passwordFields > 0)) {
      risks.push({
        type: 'hidden_fields',
        message: `${formData.hiddenFields} gizli alan tespit edildi`
      });
    }

    // Password field + external = yuksek risk
    if (formData.passwordFields > 0 && hasExternalSubmit) {
      return {
        is_safe: false,
        risk_level: 'HIGH',
        reasons: risks.map(r => r.message)
      };
    }

    // Sadece external submit (güvenli site de olabilir - OAuth, payment gateway gibi)
    if (hasExternalSubmit && formData.passwordFields === 0) {
      return {
        is_safe: true,
        risk_level: 'LOW',
        reasons: []
      };
    }

    return {
      is_safe: true,
      risk_level: 'LOW',
      reasons: []
    };
  }

  /**
   * Form uyarisi goster
   */
  function showFormWarning(form, result) {
    // Eğer zaten bir uyarı varsa ekleme
    if (document.getElementById('phishshield-form-warning')) {
      return;
    }

    const warning = document.createElement('div');
    warning.id = 'phishshield-form-warning';
    const uniqueId = Date.now();
    warning.innerHTML = `
      <div class="phishshield-form-warning-content">
        <div class="phishshield-icon">⚠️</div>
        <h3>Dikkat! Güvenlik Riski</h3>
        <p>Bu form tehlikeli olabilir:</p>
        <ul class="phishshield-reasons">
          ${result.reasons.map(r => `<li>⚠️ ${r}</li>`).join('')}
        </ul>
        <div class="phishshield-actions">
          <button id="phishshield-form-continue-${uniqueId}" class="btn-primary">
            Yine de Gonder
          </button>
          <button id="phishshield-form-cancel-${uniqueId}" class="btn-danger">
            Iptal Et
          </button>
        </div>
      </div>
    `;

    // Stil ekle
    const style = document.createElement('style');
    style.textContent = `
      #phishshield-form-warning {
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(244, 67, 54, 0.95);
        z-index: 2147483647;
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        animation: phishshield-fadein 0.3s;
      }
      @keyframes phishshield-fadein {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .phishshield-form-warning-content {
        background: white;
        color: #333;
        border-radius: 16px;
        padding: 30px;
        max-width: 450px;
        text-align: center;
        box-shadow: 0 10px 40px rgba(0,0,0,0.3);
      }
      .phishshield-icon {
        font-size: 48px;
        margin-bottom: 10px;
      }
      .phishshield-form-warning-content h3 {
        color: #F44336;
        margin: 10px 0;
        font-size: 22px;
      }
      .phishshield-form-warning-content p {
        margin: 10px 0;
        color: #666;
      }
      .phishshield-reasons {
        text-align: left;
        background: #fff3cd;
        border-radius: 8px;
        padding: 15px 20px;
        margin: 15px 0;
        list-style: none;
      }
      .phishshield-reasons li {
        margin: 8px 0;
        font-size: 14px;
      }
      .phishshield-actions {
        display: flex;
        gap: 10px;
        justify-content: center;
        margin-top: 20px;
      }
      .phishshield-actions button {
        padding: 10px 20px;
        border-radius: 8px;
        border: none;
        font-size: 14px;
        cursor: pointer;
      }
      .btn-danger {
        background: #F44336;
        color: white;
      }
      .btn-primary {
        background: #2196F3;
        color: white;
      }
      .phishshield-fade-out {
        animation: phishshield-fadeout 0.3s ease-out forwards;
      }
      @keyframes phishshield-fadeout {
        to { opacity: 0; transform: scale(0.95); }
      }
    `;

    document.head.appendChild(style);
    document.body.appendChild(warning);

    // Event listeners - benzersiz ID'leri kullan
    document.getElementById(`phishshield-form-continue-${uniqueId}`).addEventListener('click', (e) => {
      e.stopPropagation();
      warning.classList.add('phishshield-fade-out');
      setTimeout(() => warning.remove(), 300);
    });

    document.getElementById(`phishshield-form-cancel-${uniqueId}`).addEventListener('click', (e) => {
      e.stopPropagation();
      // Form submit'i engelle
      form.addEventListener('submit', (ev) => {
        ev.preventDefault();
        ev.stopPropagation();
      }, true);
      warning.classList.add('phishshield-fade-out');
      setTimeout(() => warning.remove(), 300);
    });

    // Form submit'i engelle - capture phase'da yakala
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      e.stopPropagation();
    }, true);
  }

  /**
   * Form dikkat mesaji goster
   */
  function showFormCaution(form, result) {
    const caution = document.createElement('div');
    caution.className = 'phishshield-form-caution';
    caution.innerHTML = `
      <span class="phishshield-icon">⚠️</span>
      <span class="phishshield-text">PhishShield: ${result.reasons[0] || 'Bu form satici olabilir'}</span>
    `;

    caution.style.cssText = `
      position: fixed;
      bottom: 20px;
      left: 20px;
      background: #FF9800;
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      font-size: 14px;
      z-index: 2147483646;
      display: flex;
      align-items: center;
      gap: 10px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      animation: phishshield-slidein 0.3s;
    `;

    const style = document.createElement('style');
    style.textContent = `
      @keyframes phishshield-slidein {
        from { transform: translateY(100%); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
    `;
    document.head.appendChild(style);

    document.body.appendChild(caution);

    setTimeout(() => {
      caution.style.opacity = '0';
      setTimeout(() => caution.remove(), 300);
    }, 8000);
  }

  // Listen for dynamic forms
  const formObserver = new MutationObserver((mutations) => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'FORM') {
            protectForm(node);
          }
          node.querySelectorAll?.('form').forEach(form => protectForm(form));
        }
      });
    });
  });

  formObserver.observe(document.body, {
    childList: true,
    subtree: true
  });

  // Initial scan
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      setTimeout(scanAndProtectForms, GUARD_CONFIG.checkDelay);
    });
  } else {
    setTimeout(scanAndProtectForms, GUARD_CONFIG.checkDelay);
  }

  console.log('PhishShield Form Guard loaded');
})();
