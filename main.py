from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import logging
from fastapi.responses import JSONResponse
import requests  # for making HTTP requests
from urllib.parse import urlparse

from schemas.package import PackageCheck
from schemas.security import SecurityScanResult
from services.package_scanner import PackageScanner
from services.code_scanner import CodeScanner
from services.api_scanner import APIScanner
from services.keyword_scanner import KeywordScanner

# Add logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="Silent Guardian API",
    description="Security scanner for detecting malicious packages and code",
    version="1.0.0"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows requests from frontend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Add error handling middleware
@app.middleware("http")
async def catch_exceptions_middleware(request: Request, call_next):
    try:
        return await call_next(request)
    except Exception as e:
        logger.error(f"Unhandled error: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"}
        )

# Initialize services
package_scanner = PackageScanner()
code_scanner = CodeScanner()
api_scanner = APIScanner()
keyword_scanner = KeywordScanner()

@app.get("/")
async def root():
    return {
        "message": "Welcome to Silent Guardian API",
        "version": "1.0.0",
        "endpoints": {
            "package_check": "/api/v1/check-package",
            "code_scan": "/api/v1/scan-code",
            "api_check": "/api/v1/check-api-url",
            "scan_keywords": "/api/v1/scan-keywords"
        }
    }

@app.post("/api/v1/check-package", response_model=SecurityScanResult)
async def check_package(package: PackageCheck):
    logger.info(f"Checking package: {package.name} ({package.ecosystem})")
    try:
        result = await package_scanner.scan_package(
            name=package.name,
            ecosystem=package.ecosystem,
            version=package.version
        )
        return result
    except Exception as e:
        logger.error(f"Error checking package: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan-code")
async def scan_code(request: Request):
    body = await request.json()
    code = body.get("code")
    if not code:
        raise HTTPException(status_code=400, detail="Code is required")
    try:
        result = await code_scanner.scan_code(code)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/check-api-url")
async def check_api_url(url: str):
    """
    Check if an API URL is potentially malicious
    """
    try:
        result = await api_scanner.check_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan-webpage")
async def scan_webpage(request: Request):
    body = await request.json()
    url = body.get("url")
    if not url:
        raise HTTPException(status_code=400, detail="URL is required")
    try:
        result = await code_scanner.scan_webpage(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/extension/scan")
async def scan_for_extension(request: Request):
    data = await request.json()
    url = data.get("url")
    page_content = data.get("content")
    scripts = data.get("scripts", [])

    try:
        trust_points = 100
        warnings = []
        risk_factors = []

        # Dangerous patterns (-20 points each)
        dangerous_patterns = {
            # Code Execution
            'eval(': 'Dynamic code execution',
            'new Function(': 'Dynamic code execution',
            'setTimeout(': 'Dynamic code execution',
            'setInterval(': 'Dynamic code execution',
            
            # Unsafe DOM
            'document.write(': 'Unsafe DOM manipulation',
            '.innerHTML = ': 'Unsafe HTML injection',
            
            # Credentials
            'api_key': 'Exposed credentials',
            'apikey': 'Exposed credentials',
            'secret_key': 'Exposed credentials',
            'password': 'Exposed credentials',
            'Bearer ': 'Exposed token',
            
            # Malicious
            'crypto.miner': 'Cryptocurrency mining',
            'coinhive': 'Cryptocurrency mining',
            'base64_decode(': 'Obfuscated code',
            'fromCharCode(': 'Obfuscated code',
            
            # Dangerous redirects
            'window.location = ': 'Forced redirect',
            'window.open(': 'Popup window',
            
            # Data exfiltration
            'navigator.sendBeacon(': 'Data sending',
            'websocket(': 'WebSocket connection'
        }

        # Suspicious patterns (-10 points each)
        suspicious_patterns = {
            # Storage
            'localStorage': 'Local storage usage',
            'sessionStorage': 'Session storage usage',
            'indexedDB': 'Database usage',
            
            # Network
            'fetch(': 'Network request',
            'xhr.open': 'Network request',
            'websocket': 'WebSocket usage',
            
            # Cookies
            'document.cookie': 'Cookie manipulation',
            
            # Forms
            'form.submit': 'Form submission',
            'formData': 'Form data handling',
            
            # Navigation
            'history.pushState': 'History manipulation',
            'history.replaceState': 'History manipulation'
        }

        # Safe patterns (no deduction)
        safe_patterns = {
            # Standard DOM
            'getElementById',
            'querySelector',
            'addEventListener',
            'removeEventListener',
            
            # Common frameworks
            'React',
            'Vue',
            'Angular',
            'jQuery',
            
            # Analytics
            'gtag',
            'ga',
            'fbq',
            'dataLayer',
            
            # Standard APIs
            'fetch',
            'console.log',
            'Promise',
            'async',
            'await'
        }

        for script in scripts:
            # Check for dangerous patterns
            for pattern, reason in dangerous_patterns.items():
                if pattern in script:
                    trust_points -= 20
                    warnings.append(f"⚠️ Dangerous: {reason}")
                    risk_factors.append(f"dangerous_{pattern}")

            # Check for suspicious patterns
            for pattern, reason in suspicious_patterns.items():
                if pattern in script and not any(safe in script for safe in safe_patterns):
                    trust_points -= 10
                    warnings.append(f"⚕️ Suspicious: {reason}")
                    risk_factors.append(f"suspicious_{pattern}")

        # Domain checks
        if not url.startswith('https://'):
            trust_points -= 15
            warnings.append("⚠️ Insecure connection (no HTTPS)")

        # Content checks
        if page_content:
            if '<iframe' in page_content:
                trust_points -= 10
                warnings.append("⚠️ Contains iframes")
            if 'phishing' in page_content.lower():
                trust_points -= 30
                warnings.append("⚠️ Potential phishing content")

        # Final calculations
        trust_points = max(0, min(100, trust_points))

        return {
            "trustScore": trust_points,
            "alerts": warnings,
            "isSuspicious": trust_points < 60,
            "details": {
                "risk_level": "safe" if trust_points >= 80 else "medium" if trust_points >= 60 else "high",
                "risk_factors": risk_factors
            }
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/scan-keywords")
async def scan_keywords(request: Request):
    """Scan text for sensitive keywords"""
    body = await request.json()
    text = body.get("text")
    
    if not text:
        raise HTTPException(status_code=400, detail="Text is required")
        
    try:
        result = await keyword_scanner.scan_text(text)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 