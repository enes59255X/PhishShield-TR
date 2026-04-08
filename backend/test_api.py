import httpx
import asyncio
import json

async def test_api():
    url = "http://127.0.0.1:8002/analyze"
    test_data = {"url": "https://www.google.com"}
    
    print(f"--- TEST BAŞLATILDI: {test_data['url']} ---")
    
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(url, json=test_data)
            
            if response.status_code == 200:
                print("✅ API Yanıtı Başarılı!")
                print(json.dumps(response.json(), indent=2, ensure_ascii=False))
            else:
                print(f"❌ API Hatası: {response.status_code}")
                print(response.text)
                
    except Exception as e:
        print(f"⚠️ Bağlantı Hatası: {e}")

if __name__ == "__main__":
    asyncio.run(test_api())
