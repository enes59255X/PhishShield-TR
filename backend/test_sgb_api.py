import asyncio
import aiohttp
import json

async def fetch_sgb_api():
    """Fetch malicious domains from Siber Guvenlik API"""
    base_url = 'https://siberguvenlik.gov.tr/api/address'

    async with aiohttp.ClientSession() as session:
        # Get first page with domains
        params = {'page': 1, 'count': 100, 'type': 'domain'}
        try:
            async with session.get(base_url, params=params, timeout=30, ssl=False) as resp:
                data = await resp.json()
                total = data.get('totalCount', 0)
                count = data.get('count', 0)
                models = data.get('models', [])

                print(f'Total domains in SGB: {total}')
                print(f'First page count: {count}')
                print()
                print('First 10 domains:')
                for item in models[:10]:
                    url = item.get('url', '')
                    conn_type = item.get('connectiontype', '')
                    print(f'  - {url} ({conn_type})')

                return total, models
        except Exception as e:
            print(f'Error: {e}')
            return 0, []

if __name__ == '__main__':
    total, domains = asyncio.run(fetch_sgb_api())
