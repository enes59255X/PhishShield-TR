"""
PhishShield TR - Form Behavior Analyzer
Sprint 5: Advanced credential harvesting detection
"""

import re
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class FormAnalysisResult:
    """Result of form behavior analysis"""
    has_login_form: bool = False
    has_password_field: bool = False
    has_credential_fields: bool = False
    has_payment_fields: bool = False
    has_external_submit: bool = False
    external_domain: Optional[str] = None
    form_count: int = 0
    hidden_fields: List[str] = None
    autocomplete_disabled: bool = False
    captcha_present: bool = False
    
    # Risk signals
    signals: List[str] = None
    risk_score: int = 0
    severity: str = "LOW"
    
    def __post_init__(self):
        if self.hidden_fields is None:
            self.hidden_fields = []
        if self.signals is None:
            self.signals = []


class FormBehaviorAnalyzer:
    """
    Analyzes form behavior to detect credential harvesting attempts.
    
    Key detections:
    - Login forms with external submit
    - Password fields sending data externally
    - Credit card / payment forms
    - Hidden form fields (credit card skimmers)
    - OTP/2FA field detection
    - Fake captcha
    """
    
    # Sensitive field patterns
    PASSWORD_FIELDS = [
        'password', 'passwd', 'pwd', 'pass', 'parola', 'sifre',
        'pin', 'pincode', 'security_code'
    ]
    
    # Credential fields (username, email, phone)
    CREDENTIAL_FIELDS = [
        'username', 'user', 'email', 'phone', 'tel', 'mobile',
        'tc', 'tckimlik', 'kimlik', 'identity', 'id_number',
        'ad', 'soyad', 'name', 'surname'
    ]
    
    # Payment fields
    PAYMENT_FIELDS = [
        'card', 'kart', 'credit', 'debit', 'cvv', 'cvc',
        'expiry', 'exp_date', 'month', 'year', 'iban',
        'account', 'hesap'
    ]
    
    # OTP fields
    OTP_FIELDS = [
        'otp', 'two_factor', '2fa', 'verification', 'dogrulama',
        'sms_code', 'kod', 'confirm_code'
    ]
    
    # External submit domains (known legitimate)
    KNOWN_EXTERNAL = [
        'google.com', 'facebook.com', 'apple.com', 'microsoft.com',
        'linkedin.com', 'github.com', 'twitter.com'
    ]
    
    def __init__(self):
        self.form_count = 0
    
    def analyze(self, html_content: str, page_url: str) -> FormAnalysisResult:
        """
        Analyze forms in HTML content.
        
        Args:
            html_content: Raw HTML of the page
            page_url: URL of the page (for domain comparison)
        
        Returns:
            FormAnalysisResult with findings
        """
        result = FormAnalysisResult()
        
        # Parse forms
        forms = self._extract_forms(html_content)
        result.form_count = len(forms)
        
        if not forms:
            return result
        
        page_domain = self._get_domain(page_url)
        
        for form in forms:
            form_analysis = self._analyze_form(form, page_domain)
            
            # Aggregate findings
            if form_analysis['has_password']:
                result.has_password_field = True
            if form_analysis['has_credentials']:
                result.has_credential_fields = True
            if form_analysis['has_payment']:
                result.has_payment_fields = True
            if form_analysis['external_submit']:
                result.has_external_submit = True
                result.external_domain = form_analysis['external_domain']
            if form_analysis['hidden_fields']:
                result.hidden_fields.extend(form_analysis['hidden_fields'])
            if form_analysis['autocomplete_disabled']:
                result.autocomplete_disabled = True
            if form_analysis['captcha']:
                result.captcha_present = True
                
            result.signals.extend(form_analysis['signals'])
            result.risk_score += form_analysis['risk_score']
        
        # Determine overall severity
        result.has_login_form = result.has_password_field and result.has_credential_fields
        result.risk_score = min(100, result.risk_score)
        result.severity = self._calculate_severity(result)
        
        return result
    
    def _extract_forms(self, html: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []
        
        # Simple regex-based form extraction (no BeautifulSoup dependency)
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.IGNORECASE | re.DOTALL)
        action_pattern = re.compile(r'action=["\']([^"\']*)["\']', re.IGNORECASE)
        method_pattern = re.compile(r'method=["\']([^"\']*)["\']', re.IGNORECASE)
        
        for form_match in form_pattern.finditer(html):
            form_content = form_match.group(0)
            
            action_match = action_pattern.search(form_content)
            method_match = method_pattern.search(form_content)
            
            action = action_match.group(1) if action_match else ''
            method = method_match.group(1).upper() if method_match else 'GET'
            
            forms.append({
                'html': form_content,
                'action': action,
                'method': method,
                'inputs': self._extract_inputs(form_content)
            })
        
        return forms
    
    def _extract_inputs(self, form_html: str) -> List[Dict]:
        """Extract input fields from form HTML"""
        inputs = []
        
        # Input fields
        input_pattern = re.compile(
            r'<input[^>]*>',
            re.IGNORECASE | re.DOTALL
        )
        
        for input_match in input_pattern.finditer(form_html):
            input_html = input_match.group(0)
            
            # Extract attributes
            name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            id_match = re.search(r'id=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            placeholder_match = re.search(r'placeholder=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            autocomplete_match = re.search(r'autocomplete=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
            
            # Check for hidden
            is_hidden = 'hidden' in input_html.lower()
            
            # Check for disabled autocomplete
            autocomplete_off = autocomplete_match and autocomplete_match.group(1).lower() == 'off'
            
            input_data = {
                'name': name_match.group(1) if name_match else '',
                'type': type_match.group(1).lower() if type_match else 'text',
                'id': id_match.group(1) if id_match else '',
                'placeholder': placeholder_match.group(1).lower() if placeholder_match else '',
                'hidden': is_hidden,
                'autocomplete_off': autocomplete_off
            }
            
            inputs.append(input_data)
        
        return inputs
    
    def _analyze_form(self, form: Dict, page_domain: str) -> Dict:
        """Analyze a single form for suspicious behavior"""
        analysis = {
            'has_password': False,
            'has_credentials': False,
            'has_payment': False,
            'external_submit': False,
            'external_domain': None,
            'hidden_fields': [],
            'autocomplete_disabled': False,
            'captcha': False,
            'signals': [],
            'risk_score': 0
        }
        
        inputs = form.get('inputs', [])
        
        for inp in inputs:
            name = inp['name'].lower()
            input_type = inp['type']
            placeholder = inp['placeholder']
            
            # Hidden field check
            if inp['hidden']:
                analysis['hidden_fields'].append(inp['name'])
                analysis['signals'].append('hidden_field')
                analysis['risk_score'] += 15
            
            # Autocomplete off (suspicious for login forms)
            if inp['autocomplete_off']:
                analysis['autocomplete_disabled'] = True
                analysis['signals'].append('autocomplete_disabled')
                analysis['risk_score'] += 10
            
            # Password field check
            if input_type == 'password' or any(p in name for p in self.PASSWORD_FIELDS):
                analysis['has_password'] = True
                analysis['risk_score'] += 20
            
            # Credential fields
            if any(c in name for c in self.CREDENTIAL_FIELDS):
                analysis['has_credentials'] = True
                analysis['risk_score'] += 10
            
            # Payment fields
            if any(p in name for p in self.PAYMENT_FIELDS):
                analysis['has_payment'] = True
                analysis['risk_score'] += 30
            
            # OTP fields
            if any(o in name for o in self.OTP_FIELDS):
                analysis['signals'].append('otp_field')
                analysis['risk_score'] += 25
        
        # Check form action for external submit
        action = form.get('action', '')
        if action and not action.startswith('#') and not action.startswith('/'):
            # Has explicit action URL
            action_domain = self._get_domain(action)
            if action_domain and action_domain != page_domain:
                if action_domain not in self.KNOWN_EXTERNAL:
                    analysis['external_submit'] = True
                    analysis['external_domain'] = action_domain
                    analysis['signals'].append('external_submit')
                    analysis['risk_score'] += 40
        
        # Check for captcha
        if 'captcha' in form['html'].lower() or 'recaptcha' in form['html'].lower():
            analysis['captcha'] = True
            analysis['risk_score'] -= 5  # Captcha is generally good sign
        
        # Critical: Password field + external submit = HIGH risk
        if analysis['has_password'] and analysis['external_submit']:
            analysis['signals'].append('credential_harvesting_external')
            analysis['risk_score'] += 30
        
        return analysis
    
    def _get_domain(self, url: str) -> Optional[str]:
        """Extract domain from URL"""
        try:
            if not url.startswith('http'):
                url = 'https://' + url
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0].lower()
            return domain
        except:
            return None
    
    def _calculate_severity(self, result: FormAnalysisResult) -> str:
        """Calculate overall severity"""
        if result.risk_score >= 70:
            return "CRITICAL"
        elif result.risk_score >= 40:
            return "HIGH"
        elif result.risk_score >= 20:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_signals(self, result: FormAnalysisResult) -> List[str]:
        """Convert form analysis to signal list"""
        signals = []
        
        if result.has_login_form:
            signals.append('login_form_detected')
        
        if result.has_password_field:
            signals.append('password_field')
        
        if result.has_credential_fields:
            signals.append('credential_fields')
        
        if result.has_payment_fields:
            signals.append('payment_fields')
        
        if result.has_external_submit:
            signals.append('external_submit')
            signals.append('credential_harvesting_external')
        
        if result.hidden_fields:
            signals.append('hidden_form_fields')
        
        if result.autocomplete_disabled:
            signals.append('autocomplete_disabled')
        
        if result.captcha_present:
            signals.append('captcha_present')
        
        return signals


# Singleton instance
form_analyzer = FormBehaviorAnalyzer()
