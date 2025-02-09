import asyncio
import aiohttp
from typing import Dict, Any
import json
import requests

# Define the base URL for the API
BASE_URL = "http://127.0.0.1:8000/api/v1"

# Define test cases
test_cases = [
    {
        "name": "Safe Website",
        "data": {
            "url": "https://example.com",  # Required field
            "content": "<html><h1>Welcome to Python</h1></html>",  # Optional field
            "scripts": []  # Optional field
        },
        "expected": {
            "trustScore": 100,
            "alerts": [],
            "isSuspicious": False,
            "details": {
                "risk_level": "safe",
                "risk_factors": []
            }
        }
    },
    {
        "name": "Piracy Website",
        "data": {
            "url": "https://www.pirateproxy-bay.com/",
            "content": "Download torrents here! Hide your IP with VPN. Free movies and cracked software.",
            "scripts": []
        },
        "expected": {
            "trustScore": 45,
            "alerts": ["⚠️ Insecure connection (no HTTPS)", "⚠️ Piracy content detected"],
            "isSuspicious": True,
            "details": {
                "risk_level": "high",
                "risk_factors": []
            }
        }
    },
    {
        "name": "Empty URL",
        "data": {
            "url": "",
            "content": "",
            "scripts": []
        },
        "expected": {
            "detail": "400: Invalid input: 'url' must be a valid string."
        }
    },
    {
        "name": "Long URL",
        "data": {
            "url": "https://example.com/" + "a" * 1000,
            "content": "",
            "scripts": []
        },
        "expected": {
            "trustScore": 80,  # Adjusted for long URL penalty
            "isSuspicious": False,
            "alerts": ["⚠️ URL is unusually long"],
            "details": {}
        }
    },
    # Add more test cases as needed
]

# Function to test the extension scanner
def test_extension_scanner():
    for case in test_cases:
        print(f"Testing: {case['name']}")
        print(f"URL: {case['data']['url']}")  # Debug log
        response = requests.post(f"{BASE_URL}/extension/scan", json=case["data"])
        result = response.json()
        if result == case["expected"]:
            print("✅ Test passed")
        else:
            print(f"❌ Test failed: {result}")
            print(f"Full error: {result}")

async def test_all():
    async with aiohttp.ClientSession() as session:
        print("\n1. Testing Extension Scanner...")
        test_extension_scanner()

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