"""
PhishShield TR - SGB (Siber Guvenlik Baskanligi) Source
Sprint 15: Real API integration for threat intelligence

Uses: https://siberguvenlik.gov.tr/api/address
"""

import asyncio
import aiohttp
from datetime import datetime
from typing import List, Dict, Optional

from ..models import ThreatMatch, ThreatSeverity


class USOMSource:
    """
    SGB (Siber Guvenlik Baskanligi) threat intelligence source.

    Uses the official API: https://siberguvenlik.gov.tr/api/address
    """

    SOURCE_NAME = "sgb"
    API_URL = "https://siberguvenlik.gov.tr/api/address"

    def __init__(self):
        self.name = "SGB"
        self.source_type = "sgb"
        self.threat_level = 10
        self.last_update: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.enabled = True

    async def fetch(self) -> List[str]:
        """
        Fetch domains from Siber Guvenlik Baskanligi API.

        Returns:
            List of malicious domains
        """
        domains = []

        try:
            page = 1
            total_fetched = 0
            max_pages = 50  # Reduced
            max_domains = 5000  # Reduced

            async with aiohttp.ClientSession() as session:
                while total_fetched < max_domains and page <= max_pages:
                    params = {
                        'page': page,
                        'count': 100,
                        'type': 'domain'
                    }

                    try:
                        async with session.get(
                            self.API_URL,
                            params=params,
                            timeout=aiohttp.ClientTimeout(total=10),  # 10s timeout per page
                            ssl=False
                        ) as response:
                            if response.status != 200:
                                self.last_error = f"HTTP {response.status}"
                                break

                            data = await response.json()
                            models = data.get('models', [])

                            if not models:
                                break

                            for item in models:
                                url = item.get('url', '')
                                if url:
                                    domains.append(url)
                                    total_fetched += 1

                            total_count = data.get('totalCount', 0)
                            if page * 100 >= total_count:
                                break

                            page += 1
                            await asyncio.sleep(0.05)  # Small delay

                    except asyncio.TimeoutError:
                        print(f"SGB page {page} timeout, continuing...")
                        break
                    except asyncio.CancelledError:
                        print("SGB fetch cancelled")
                        break

            if domains:
                self.last_update = datetime.now()
                self.last_error = None
                print(f"SGB: Fetched {len(domains)} malicious domains")

        except Exception as e:
            self.last_error = str(e)
            print(f"SGB fetch error: {e}")

        return domains

    def to_threat_match(self, domain: str) -> ThreatMatch:
        """Convert domain to ThreatMatch"""
        return ThreatMatch(
            is_threat=True,
            domain=domain,
            source=self.SOURCE_NAME,
            category="phishing",
            severity=ThreatSeverity.CRITICAL.value,
            confidence=0.98,
            first_seen=self.last_update,
            last_seen=self.last_update,
            tags=["phishing", "sgb", "turkiye"],
            reference_url="https://siberguvenlik.gov.tr/"
        )

    def get_status(self) -> Dict:
        """Get source status"""
        return {
            "name": self.name,
            "status": "OK" if self.last_error is None else "ERROR",
            "last_update": self.last_update.isoformat() if self.last_update else None,
            "last_error": self.last_error,
            "threat_level": self.threat_level
        }
