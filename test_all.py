import asyncio
import aiohttp
import ssl

async def test_all():
    # Create SSL context that doesn't verify certificates
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE
    
    # Use the SSL context in ClientSession - simpler SSL config
    async with aiohttp.ClientSession(
        connector=aiohttp.TCPConnector(ssl=None)  # Just disable SSL checks
    ) as session:
        print("\n1. Testing Package Scanner...")
        packages_to_test = [
            {"name": "requests", "ecosystem": "pypi"},
            {"name": "reqeusts", "ecosystem": "pypi"}
        ]
        
        for pkg in packages_to_test:
            try:
                async with session.post(
                    'http://localhost:8000/api/v1/check-package',
                    json=pkg
                ) as response:
                    result = await response.json()
                    print(f"\nPackage: {pkg['name']}")
                    print(f"Result: {result}")
            except Exception as e:
                print(f"Error testing package {pkg['name']}: {str(e)}")

        print("\n2. Testing Code Scanner...")
        code_samples = [
            "print('hello')",  # Safe code
            "eval(input())",   # Suspicious code
            "os.system('rm -rf /')"  # Dangerous code
        ]
        
        for code in code_samples:
            try:
                async with session.post(
                    'http://localhost:8000/api/v1/scan-code',
                    json={"code": code}
                ) as response:
                    result = await response.json()
                    print(f"\nCode: {code}")
                    print(f"Result: {result}")
            except Exception as e:
                print(f"Error scanning code: {str(e)}")

        print("\n3. Testing Web Scanner...")
        urls_to_test = [
            "https://example.com",
            "https://api-goggle.com"
        ]
        
        for url in urls_to_test:
            try:
                async with session.post(
                    'http://localhost:8000/api/v1/scan-webpage',
                    json={"url": url}
                ) as response:
                    result = await response.json()
                    print(f"\nURL: {url}")
                    print(f"Result: {result}")
            except Exception as e:
                print(f"Error scanning URL {url}: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_all()) 