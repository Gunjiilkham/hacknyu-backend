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
        print("\n1. Testing Extension Scanner...")
        test_cases = [
            {
                "name": "Safe Website",
                "data": {
                    "url": "https://python.org",
                    "content": "<html><h1>Welcome to Python</h1></html>",
                    "scripts": ["console.log(\"Hello\")"]
                },
                "expected_score": 100
            },
            {
                "name": "Suspicious Code",
                "data": {
                    "url": "https://example.com",
                    "content": "<html><script>eval(\"alert(1)\")</script></html>",
                    "scripts": ["eval(\"alert(1)\")"]
                },
                "expected_score": 30
            },
            {
                "name": "Phishing Site",
                "data": {
                    "url": "https://pyth0n.org",
                    "content": "<html>Login to Python</html>",
                    "scripts": []
                },
                "expected_score": 30
            },
            {
                "name": "Sensitive Data",
                "data": {
                    "url": "https://example.com",
                    "content": "API_KEY=abc123",
                    "scripts": []
                },
                "expected_score": 30
            }
        ]

        for case in test_cases:
            try:
                print(f"\nTesting: {case['name']}")
                async with session.post(
                    'http://localhost:8000/api/v1/extension/scan',
                    json=case['data']
                ) as response:
                    result = await response.json()
                    print(f"Result: {result}")
                    
                    # Verify response format
                    assert "trustScore" in result, "Missing trustScore"
                    assert "alerts" in result, "Missing alerts"
                    assert "isSuspicious" in result, "Missing isSuspicious"
                    assert "details" in result, "Missing details"
                    
                    # Verify expected score
                    assert result["trustScore"] == case["expected_score"], \
                        f"Expected score {case['expected_score']}, got {result['trustScore']}"
                    
                    print("✅ Test passed!")
            except Exception as e:
                print(f"❌ Test failed: {str(e)}")

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

        print("\n4. Testing Keyword Scanner...")
        test_texts = [
            "This is a normal text",
            "The password is 12345",
            "API_KEY=abc123 SECRET_KEY=xyz789",
            "Please enter your credit card number"
        ]

        for text in test_texts:
            try:
                async with session.post(
                    'http://localhost:8000/api/v1/scan-keywords',
                    json={"text": text}
                ) as response:
                    result = await response.json()
                    print(f"\nText: {text}")
                    print(f"Result: {result}")
            except Exception as e:
                print(f"Error scanning text: {str(e)}")

if __name__ == "__main__":
    asyncio.run(test_all()) 