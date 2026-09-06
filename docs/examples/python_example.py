"""
PhishShield TR API - Python Usage Examples

Bu dosya PhishShield TR API'sinin Python ile nasıl kullanılacağını gösterir.
"""

import requests
import json
from typing import Dict, List, Optional


class PhishShieldClient:
    """PhishShield TR API Client"""
    
    def __init__(self, api_key: str, base_url: str = "http://127.0.0.1:8004"):
        self.api_key = api_key
        self.base_url = base_url
        self.headers = {
            "X-API-Key": api_key,
            "Content-Type": "application/json"
        }
    
    def check_url(self, url: str, check_type: str = "full") -> Dict:
        """
        URL analizi yapar.
        
        Args:
            url: Analiz edilecek URL
            check_type: "quick" veya "full"
            
        Returns:
            Analiz sonucu dict
        """
        response = requests.post(
            f"{self.base_url}/api/v2/check",
            json={"url": url, "check_type": check_type},
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def batch_check(self, urls: List[str]) -> Dict:
        """
        Birden fazla URL'yi analiz eder.
        
        Args:
            urls: URL listesi (max 100)
            
        Returns:
            Toplu analiz sonuçları
        """
        response = requests.post(
            f"{self.base_url}/api/v2/batch",
            json={"urls": urls},
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def explain(self, url: str, risk_score: int, 
                decision: str, components: Dict) -> Dict:
        """
        Analiz sonucunun detaylı açıklamasını alır.
        
        Args:
            url: URL
            risk_score: Risk skoru (0-100)
            decision: Karar (PHISHING/SAFE/SUSPICIOUS)
            components: Bileşen skorları
            
        Returns:
            Detaylı açıklama
        """
        response = requests.post(
            f"{self.base_url}/api/v2/explain",
            json={
                "url": url,
                "risk_score": risk_score,
                "decision": decision,
                "components": components
            },
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def get_domain_intel(self, domain: str) -> Dict:
        """
        Domain hakkında detaylı bilgi alır.
        
        Args:
            domain: Domain adı
            
        Returns:
            Domain zeka bilgisi
        """
        response = requests.get(
            f"{self.base_url}/api/v2/intel/domain/{domain}",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def submit_feedback(self, url: str, feedback_type: str,
                        original_decision: str = None,
                        original_score: int = None,
                        message: str = None) -> Dict:
        """
        Geri bildirim gönderir.
        
        Args:
            url: URL
            feedback_type: false_positive / false_negative / correct
            original_decision: Orijinal karar
            original_score: Orijinal skor
            message: Mesaj
            
        Returns:
            Geri bildirim sonucu
        """
        data = {
            "url": url,
            "feedback_type": feedback_type
        }
        
        if original_decision:
            data["original_decision"] = original_decision
        if original_score:
            data["original_score"] = original_score
        if message:
            data["message"] = message
            
        response = requests.post(
            f"{self.base_url}/api/v2/feedback",
            json=data,
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def get_stats(self) -> Dict:
        """Sistem istatistiklerini alır."""
        response = requests.get(
            f"{self.base_url}/api/v2/stats",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()
    
    def health_check(self) -> Dict:
        """Sistem sağlık durumunu kontrol eder."""
        response = requests.get(
            f"{self.base_url}/health",
            headers=self.headers
        )
        response.raise_for_status()
        return response.json()


def main():
    # API anahtarınızı buraya girin
    API_KEY = "psh_your_api_key_here"
    
    # İstemci oluştur
    client = PhishShieldClient(API_KEY)
    
    print("=" * 60)
    print("PhishShield TR API - Python Örnekleri")
    print("=" * 60)
    
    # 1. Tek URL analizi
    print("\n1. URL Analizi:")
    print("-" * 40)
    result = client.check_url("https://garanti-login-secure.xyz.com")
    print(f"URL: {result['url']}")
    print(f"Karar: {result['decision']}")
    print(f"Risk Skoru: {result['risk_score']}")
    print(f"Güven: {result['confidence']}%")
    
    # 2. Detaylı açıklama
    print("\n2. Detaylı Açıklama:")
    print("-" * 40)
    explanation = client.explain(
        url=result['url'],
        risk_score=result['risk_score'],
        decision=result['decision'],
        components=result['components']
    )
    print(f"Başlık: {explanation['headline']}")
    print(f"Özet: {explanation['summary']}")
    print("Kırmızı Bayraklar:")
    for flag in explanation['red_flags']:
        print(f"  - {flag}")
    
    # 3. Toplu analiz
    print("\n3. Toplu URL Analizi:")
    print("-" * 40)
    urls = [
        "https://google.com",
        "https://akbank.com",
        "https://garanti-login.xyz"
    ]
    batch_result = client.batch_check(urls)
    print(f"Toplam: {batch_result['summary']['total']}")
    print(f"Phishing: {batch_result['summary']['phishing']}")
    print(f"Güvenli: {batch_result['summary']['safe']}")
    
    # 4. Domain zeka
    print("\n4. Domain Zeka:")
    print("-" * 40)
    intel = client.get_domain_intel("akbank.com")
    print(f"Domain: {intel['domain']}")
    print(f"Yaş: {intel['age_days']} gün")
    print(f"SSL: {'Var' if intel['ssl_info']['has_ssl'] else 'Yok'}")
    
    # 5. Geri bildirim
    print("\n5. Geri Bildirim:")
    print("-" * 40)
    feedback = client.submit_feedback(
        url="https://some-url.com",
        feedback_type="false_positive",
        message="Bu aslında güvenli"
    )
    print(f"Başarılı: {feedback['success']}")
    print(f"Mesaj: {feedback['message']}")
    
    # 6. İstatistikler
    print("\n6. Sistem İstatistikleri:")
    print("-" * 40)
    stats = client.get_stats()
    print(f"Toplam İstek: {stats['total_requests']:,}")
    print(f"Tespit Edilen Phishing: {stats['phishing_detected']:,}")
    print(f"Threat DB Boyutu: {stats['threat_db_size']:,}")
    print(f"Ortalama Yanıt Süresi: {stats['avg_response_time_ms']}ms")


if __name__ == "__main__":
    main()
