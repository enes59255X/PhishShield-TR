import httpx
import asyncio
from db.database import add_to_blacklist, is_blacklisted, add_to_whitelist

USOM_FEED_URL = "https://www.usom.gov.tr/url-list.txt"

class IntelManager:
    async def check_url_intel(self, url: str) -> dict:
        """
        Checks if URL is in our local threat intelligence database.
        """
        blacklisted = await is_blacklisted(url)
        if blacklisted:
            return {"score": 100, "found": True, "source": "threat_intel"}
        return {"score": 0, "found": False}

    async def fetch_external_feeds(self):
        """
        Periodically fetches external feeds and populates whitelist.
        """
        # 1. Populate Whitelist
        await self.populate_whitelist()

        # 2. Fetch USOM
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(USOM_FEED_URL)
                if resp.status_code == 200:
                    urls = resp.text.splitlines()
                    count = 0
                    for url in urls[:500]:
                        if url.strip():
                            await add_to_blacklist(url.strip(), source="USOM")
                            count += 1
                    print(f"IntelManager: Added {count} URLs from USOM.")
        except Exception as e:
            print(f"IntelManager error: {e}")

    async def populate_whitelist(self):
        trusted = [
            "turkiye.gov.tr", "usom.gov.tr", "btk.gov.tr", "egm.gov.tr", 
            "gib.gov.tr", "meb.gov.tr", "saglik.gov.tr", "e-devlet.gov.tr",
            ".gov.tr", ".edu.tr", ".bel.tr", ".pol.tr",
            "google.com", "microsoft.com", "apple.com", "github.com",
            "tcmb.gov.tr", "ziraatbank.com.tr", "isbank.com.tr", "halkbank.com.tr"
        ]
        for domain in trusted:
            await add_to_whitelist(domain)
        print("IntelManager: Whitelist updated with official domains.")

# Global instance
intel_manager = IntelManager()
