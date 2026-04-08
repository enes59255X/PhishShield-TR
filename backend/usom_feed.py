#!/usr/bin/env python3
"""
PhishShield TR - USOM (Ulusal Siber Olaylara Müdahale Merkezi) Feed Entegrasyonu
USOM'dan phishing URL'leri otomatik çekme ve veritabanına ekleme
"""

import requests
import xml.etree.ElementTree as ET
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from database_manager import db_manager

class USOMFeed:
    """USOM API'den phishing verilerini çek ve yönet"""
    
    USOM_XML_URL = "https://www.usom.gov.tr/url-list.xml"
    USOM_JSON_URL = "https://api.usom.gov.tr/v1/domain"
    USOM_ALTERNATIVE_URL = "https://www.usom.gov.tr/adres-listesi"
    
    def __init__(self):
        self.last_update = None
        self.cached_domains = []
        self.update_interval = 3600  # 1 saat
    
    async def fetch_usom_data(self) -> List[Dict]:
        """USOM'dan phishing URL listesini çek"""
        phishing_data = []
        
        try:
            # XML feed'i dene
            async with aiohttp.ClientSession() as session:
                async with session.get(self.USOM_XML_URL, timeout=30) as response:
                    if response.status == 200:
                        xml_content = await response.text()
                        phishing_data = self._parse_xml_feed(xml_content)
                        print(f"✓ USOM XML'den {len(phishing_data)} phishing URL çekildi")
        except Exception as e:
            print(f"✗ USOM XML çekme hatası: {e}")
        
        # XML başarısız olursa JSON API dene
        if not phishing_data:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(self.USOM_JSON_URL, timeout=30) as response:
                        if response.status == 200:
                            json_data = await response.json()
                            phishing_data = self._parse_json_feed(json_data)
                            print(f"✓ USOM JSON'dan {len(phishing_data)} phishing URL çekildi")
            except Exception as e:
                print(f"✗ USOM JSON çekme hatası: {e}")
        
        self.last_update = datetime.now()
        return phishing_data
    
    def _parse_xml_feed(self, xml_content: str) -> List[Dict]:
        """USOM XML feed'ini parse et"""
        phishing_list = []
        
        try:
            root = ET.fromstring(xml_content)
            
            # USOM XML yapısına göre parse et
            for url_elem in root.findall('.//url'):
                url = url_elem.text.strip() if url_elem.text else ""
                if url:
                    phishing_list.append({
                        "url": url,
                        "domain": self._extract_domain(url),
                        "source": "USOM",
                        "threat_type": "phishing",
                        "threat_level": 10,
                        "date_added": datetime.now().isoformat()
                    })
            
            # Alternative XML formatları için
            for entry in root.findall('.//entry'):
                url_elem = entry.find('url') or entry.find('link')
                if url_elem is not None and url_elem.text:
                    url = url_elem.text.strip()
                    phishing_list.append({
                        "url": url,
                        "domain": self._extract_domain(url),
                        "source": "USOM",
                        "threat_type": "phishing", 
                        "threat_level": 10,
                        "date_added": datetime.now().isoformat()
                    })
                    
        except ET.ParseError as e:
            print(f"XML parse hatası: {e}")
        
        return phishing_list
    
    def _parse_json_feed(self, json_data: dict or list) -> List[Dict]:
        """USOM JSON API yanıtını parse et - çeşitli formatları destekler"""
        phishing_list = []
        
        try:
            # USOM JSON yapısı farklı formatlarda olabilir
            data = []
            if isinstance(json_data, list):
                data = json_data
            elif isinstance(json_data, dict):
                data = json_data.get("data", json_data.get("results", json_data.get("domains", json_data.get("items", []))))
            
            for item in data:
                if isinstance(item, str):
                    # Basit string formatı
                    url = item
                elif isinstance(item, dict):
                    url = item.get("url", item.get("address", item.get("domain", item.get("name", ""))))
                else:
                    continue
                    
                if url and len(url) > 3:
                    phishing_list.append({
                        "url": url,
                        "domain": self._extract_domain(url),
                        "source": "USOM",
                        "threat_type": item.get("type", "phishing") if isinstance(item, dict) else "phishing",
                        "threat_level": item.get("severity", 10) if isinstance(item, dict) else 10,
                        "description": item.get("description", "USOM tarafından engellenmiş") if isinstance(item, dict) else "USOM tarafından engellenmiş",
                        "date_added": datetime.now().isoformat()
                    })
        except Exception as e:
            print(f"JSON parse hatası: {e}")
        
        return phishing_list
    
    def _extract_domain(self, url: str) -> str:
        """URL'den domain çıkar"""
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.netloc.lower() if parsed.netloc else url.lower()
        except:
            return url.lower()
    
    async def update_phishing_database(self) -> int:
        """USOM verilerini veritabanına ekle"""
        phishing_data = await self.fetch_usom_data()
        added_count = 0
        
        for item in phishing_data:
            try:
                domain = item.get("domain", "")
                if domain and len(domain) > 3:  # Geçerli domain kontrolü
                    await db_manager.add_phishing_domain(
                        domain=domain,
                        threat_level=item.get("threat_level", 10),
                        source=f"USOM-{item.get('threat_type', 'phishing')}"
                    )
                    added_count += 1
            except Exception as e:
                # Duplicate entry hatalarını atla
                if "UNIQUE" not in str(e) and "duplicate" not in str(e).lower():
                    print(f"Domain ekleme hatası {domain}: {e}")
        
        print(f"✓ USOM'dan {added_count} yeni phishing domain eklendi")
        return added_count
    
    async def get_cached_phishing_domains(self) -> List[str]:
        """Cache'lenmiş phishing domain listesini döndür"""
        # Eğer cache boşsa veya güncelleme süresi geçtiyse yenile
        if not self.cached_domains or (self.last_update and 
            (datetime.now() - self.last_update).seconds > self.update_interval):
            await self.update_phishing_database()
            self.cached_domains = await db_manager.get_phishing_domains()
        
        return self.cached_domains
    
    async def is_phishing(self, url: str) -> tuple[bool, Optional[str]]:
        """URL'nin USOM listesinde olup olmadığını kontrol et"""
        domain = self._extract_domain(url)
        phishing_domains = await self.get_cached_phishing_domains()
        
        for phish_domain in phishing_domains:
            if phish_domain in domain or domain in phish_domain:
                return True, f"USOM listesinde phishing domain: {phish_domain}"
        
        return False, None

# Singleton instance
usom_feed = USOMFeed()

# Test fonksiyonu
async def test_usom_feed():
    """USOM feed'ini test et"""
    print("USOM Feed Test Başlatılıyor...")
    
    usom = USOMFeed()
    count = await usom.update_phishing_database()
    
    print(f"Toplam {count} phishing domain eklendi")
    
    # Test URL kontrolü
    test_urls = [
        "https://example.com",
        "https://tebleherseyhazir.click"
    ]
    
    for url in test_urls:
        is_phish, reason = await usom.is_phishing(url)
        print(f"{url}: {'PHISHING - ' + reason if is_phish else 'Güvenli'}")

if __name__ == "__main__":
    asyncio.run(test_usom_feed())
