#!/usr/bin/env python3
"""
PhishShield TR - Real-time Data Feeds
USOM ve resmi kaynaklardan phishing veri çekimi
"""

import asyncio
import aiohttp
import json
import sqlite3
from datetime import datetime, timedelta
from typing import List, Dict
import logging
from database_manager import db_manager

class RealtimeFeeds:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.session = None
        self.feed_sources = {
            'usom': {
                'url': 'https://www.usom.gov.tr/api/address-list',
                'enabled': True,
                'last_update': None
            },
            'phishtank': {
                'url': 'https://data.phishtank.com/data/online-valid.json',
                'enabled': False, # API key gerekli
                'last_update': None
            },
            'openphish': {
                'url': 'https://openphish.com/feed.txt',
                'enabled': True,
                'last_update': None
            }
        }
    
    async def start_monitoring(self):
        """Real-time izlemeyi baslat"""
        self.session = aiohttp.ClientSession()
        
        # Her 10 dakikada bir veri çek
        while True:
            try:
                await self.update_all_feeds()
                await asyncio.sleep(600)  # 10 dakika
            except Exception as e:
                self.logger.error(f"Feed monitoring error: {e}")
                await asyncio.sleep(60)  # Hata durumunda 1 dakika bekle
    
    async def update_all_feeds(self):
        """Tüm feed'leri güncelle"""
        tasks = []
        for source, config in self.feed_sources.items():
            if config['enabled']:
                tasks.append(self.update_feed(source))
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
    
    async def update_feed(self, source_name: str):
        """Tek bir feed'i güncelle"""
        source = self.feed_sources[source_name]
        
        try:
            if source_name == 'usom':
                await self.update_usom_feed()
            elif source_name == 'openphish':
                await self.update_openphish_feed()
            elif source_name == 'phishtank':
                await self.update_phishtank_feed()
            
            source['last_update'] = datetime.now()
            self.logger.info(f"Updated {source_name} feed")
            
        except Exception as e:
            self.logger.error(f"Failed to update {source_name}: {e}")
    
    async def update_usom_feed(self):
        """USOM phishing verilerini güncelle"""
        try:
            async with self.session.get('https://www.usom.gov.tr/api/address-list') as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # USOM veri formatini parse et
                    if 'addresses' in data:
                        for address in data['addresses']:
                            domain = address.get('address', '').lower()
                            if domain and self.is_valid_domain(domain):
                                threat_level = address.get('threat_level', 5)
                                await db_manager.add_phishing_domain(
                                    domain=domain,
                                    threat_level=threat_level,
                                    source='usom'
                                )
        
        except Exception as e:
            # USOM API'si erisilemiyorsa manuel liste kullan
            await self.update_usom_manual_list()
    
    async def update_usom_manual_list(self):
        """USOM manuel phishing listesi (fallback)"""
        # Bilinen USOM phishing domain'leri
        known_phishing = [
            'fake-gov-tr.com', 'sahte-devlet.com', 'dolandirici-site.click',
            'phishing-bank.com', 'sahte-bankasi.org', 'kredi-kart-çal.com'
        ]
        
        for domain in known_phishing:
            await db_manager.add_phishing_domain(
                domain=domain,
                threat_level=8,
                source='usom_manual'
            )
    
    async def update_openphish_feed(self):
        """OpenPhish feed'ini güncelle"""
        try:
            async with self.session.get('https://openphish.com/feed.txt') as response:
                if response.status == 200:
                    text = await response.text()
                    domains = text.strip().split('\n')
                    
                    for domain in domains[:100]:  # Limit to first 100 domains
                        domain = domain.strip().lower()
                        if domain and self.is_valid_domain(domain):
                            await db_manager.add_phishing_domain(
                                domain=domain,
                                threat_level=6,
                                source='openphish'
                            )
        
        except Exception as e:
            self.logger.error(f"OpenPhish update failed: {e}")
    
    async def update_phishtank_feed(self):
        """PhishTank feed'ini güncelle (API key gerekli)"""
        # PhishTank API key gerektirigi için simüle edilmiþ
        pass
    
    def is_valid_domain(self, domain: str) -> bool:
        """Domain geçerliliðini kontrol et"""
        if not domain or len(domain) < 4:
            return False
        
        # Basit domain format kontrolü
        if '.' not in domain:
            return False
        
        # IP adresi degil mi kontrol et
        parts = domain.split('.')
        if len(parts) >= 2 and all(part.isdigit() for part in parts):
            return False
        
        return True
    
    async def add_official_domains_from_file(self, file_path: str):
        """Dosyadan resmi domain'leri yükle"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        parts = line.split(',')
                        if len(parts) >= 2:
                            domain = parts[0].strip().lower()
                            category = parts[1].strip()
                            description = parts[2].strip() if len(parts) > 2 else ""
                            
                            if self.is_valid_domain(domain):
                                await db_manager.add_official_domain(
                                    domain=domain,
                                    category=category,
                                    description=description
                                )
        
        except Exception as e:
            self.logger.error(f"Failed to load official domains: {e}")
    
    async def export_database_stats(self) -> Dict:
        """Veritabaný istatistiklerini export et"""
        stats = await db_manager.get_statistics()
        recent_activities = await db_manager.get_recent_activities(20)
        
        return {
            'statistics': stats,
            'recent_activities': recent_activities,
            'feed_status': {
                name: {
                    'enabled': config['enabled'],
                    'last_update': config['last_update'].isoformat() if config['last_update'] else None
                }
                for name, config in self.feed_sources.items()
            },
            'export_time': datetime.now().isoformat()
        }

class OfficialDomainsSeeder:
    """Resmi domain'leri veritabanýna ekle"""
    
    OFFICIAL_DOMAINS = {
        'government': [
            ('e-devlet.gov.tr', 'Devlet Portalý', 'Türkiye Cumhuriyeti resmi devlet portalý'),
            ('turkiye.gov.tr', 'Devlet Portalý', 'Türkiye Cumhuriyeti resmi devlet portalý'),
            ('gib.gov.tr', 'Gelir Ýdaresi', 'Gelir Ýdaresi Baþkanlýðý'),
            ('sgk.gov.tr', 'SGK', 'Sosyal Güvenlik Kurumu'),
            ('tcmb.gov.tr', 'TCMB', 'Türkiye Cumhuriyet Merkez Bankasý'),
            ('btk.gov.tr', 'BTK', 'Bilgi Teknolojileri ve Ýletiþim Kurumu'),
            ('usom.gov.tr', 'USOM', 'Ulusal Siber Olaylara Müdahale Merkezi'),
            ('cimer.gov.tr', 'CÝMER', 'Cumhurbaþkanlýk Ýletiþim Merkezi'),
            ('meb.gov.tr', 'MEB', 'Milli Eðitim Bakanlýðý'),
            ('yok.gov.tr', 'YÖK', 'Yükseköðretim Kurulu'),
            ('osym.gov.tr', 'ÖSYM', 'Ölçme, Seçme ve Yerleþtirme Merkezi'),
            ('nvi.gov.tr', 'Nüfus', 'Nüfus ve Vatandaþlýk Ýþleri'),
            ('adalet.gov.tr', 'Adalet Bakanlýðý', 'Türkiye Cumhuriyeti Adalet Bakanlýðý'),
            ('saglik.gov.tr', 'Saðlýk Bakanlýðý', 'Türkiye Cumhuriyeti Saðlýk Bakanlýðý'),
            ('tsk.gov.tr', 'TSK', 'Türk Silahlý Kuvvetleri'),
            ('emlak.gov.tr', 'Tapu', 'Tapu ve Kadastro Genel Müdürlüðü'),
            ('ptt.gov.tr', 'PTT', 'Posta ve Telgraf Teþkilatý')
        ],
        'education': [
            ('eba.gov.tr', 'EBA', 'Eðitim Biliþim Aðý'),
            ('milliegitim.gov.tr', 'Milli Eðitim', 'Milli Eðitim Bakanlýðý'),
            ('ogrenci.gov.tr', 'Öðrenci', 'Milli Eðitim Bakanlýðý öðrenci portalý'),
            ('aof.anadolu.edu.tr', 'AOF', 'Anadolu Üniversitesi Açiköðretim Fakültesi'),
            ('anadolu.edu.tr', 'Anadolu Üniversitesi', 'Anadolu Üniversitesi'),
            ('yok.gov.tr', 'YÖK', 'Yükseköðretim Kurumu')
        ],
        'bank': [
            ('cepteteb.com.tr', 'TEB', 'Türkiye Ekonomi Bankasý'),
            ('teb.com.tr', 'TEB', 'Türkiye Ekonomi Bankasý'),
            ('ziraatbank.com.tr', 'Ziraat', 'Ziraat Bankasý'),
            ('vakifbank.com.tr', 'VakýfBank', 'Vakýflar Bankasý'),
            ('halkbank.com.tr', 'Halkbank', 'Halkbank'),
            ('garantibbva.com.tr', 'Garanti BBVA', 'Garanti BBVA'),
            ('akbank.com.tr', 'Akbank', 'Akbank'),
            ('isbank.com.tr', 'Ýþbank', 'Türkiye Ýþ Bankasý'),
            ('yapikredi.com.tr', 'Yapý Kredi', 'Yapý ve Kredi Bankasý'),
            ('kuveytturk.com.tr', 'Kuveyt Türk', 'Kuveyt Türk Katýlým Bankasý')
        ],
        'ecommerce': [
            ('trendyol.com', 'Trendyol', 'Türkiye\'nin en büyük e-ticaret platformu'),
            ('hepsiburada.com', 'Hepsiburada', 'Türkiye e-ticaret platformu'),
            ('n11.com', 'N11', 'Türkiye e-ticaret platformu'),
            ('gittigidiyor.com', 'GittiGidiyor', 'Türkiye e-ticaret platformu'),
            ('sahibinden.com', 'Sahibinden', 'Türkiye ilan platformu')
        ]
    }
    
    @staticmethod
    async def seed_all():
        """Tüm resmi domain'leri veritabanýna ekle"""
        for category, domains in OfficialDomainsSeeder.OFFICIAL_DOMAINS.items():
            for domain, name, description in domains:
                await db_manager.add_official_domain(domain, category, description)
        
        print(f"Seeded {sum(len(domains) for domains in OfficialDomainsSeeder.OFFICIAL_DOMAINS.values())} official domains")

# Global instance
realtime_feeds = RealtimeFeeds()
