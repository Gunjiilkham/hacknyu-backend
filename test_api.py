import asyncio
import aiohttp
import pytest

async def test_api():
    async with aiohttp.ClientSession() as session:
        print("\nTesting Extension Scanner API...")
        
        # Test 1: Safe website
        print("\nTesting safe website...")
        response = await session.post(
            'http://localhost:8000/api/v1/extension/scan',
            json={
                "url": "https://python.org",
                "content": "<html><h1>Welcome to Python</h1></html>",
                "scripts": ["console.log(\"Hello\")"]
            }
        )
        result = await response.json()
        assert result["trustScore"] == 100
        assert not result["isSuspicious"]
        print("✅ Safe website test passed")

        # Test 2: Malicious code
        print("\nTesting malicious code...")
        response = await session.post(
            'http://localhost:8000/api/v1/extension/scan',
            json={
                "url": "https://example.com",
                "content": "<html><script>eval(\"alert(1)\")</script></html>",
                "scripts": ["eval(\"alert(1)\")"]
            }
        )
        result = await response.json()
        assert result["trustScore"] == 30
        assert result["isSuspicious"]
        assert any("CRITICAL" in alert for alert in result["alerts"])
        print("✅ Malicious code test passed")

        # Test 3: Error handling
        print("\nTesting error handling...")
        response = await session.post(
            'http://localhost:8000/api/v1/extension/scan',
            json={}  # Missing required data
        )
        assert response.status in (400, 500)
        print("✅ Error handling test passed")

if __name__ == "__main__":
    asyncio.run(test_api()) 