from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Optional
import logging
from fastapi.responses import JSONResponse
import requests  # for making HTTP requests

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
    """Endpoint for browser extension to scan current webpage"""
    data = await request.json()
    url = data.get("url")
    page_content = data.get("content")  # HTML content from current page
    scripts = data.get("scripts", [])   # All scripts from the page

    try:
        code_scanner = CodeScanner()
        keyword_scanner = KeywordScanner()  # Add keyword scanner
        
        warnings = []
        suspicious_elements = []

        # 1. Check domain safety
        if code_scanner._is_suspicious_domain(url):
            warnings.append({
                "type": "domain",
                "level": "high",
                "message": "⚠️ This might be a phishing website",
                "similar_to": code_scanner._find_similar_domain(url)
            })

        # 2. Scan all scripts on the page
        for script in scripts:
            result = await code_scanner.analyze_code(script)
            if result.is_suspicious:
                suspicious_elements.append({
                    "type": "script",
                    "warnings": result.warnings,
                    "risk_level": result.risk_level
                })

        # 3. NEW: Scan page content for sensitive keywords
        if page_content:
            keyword_result = await keyword_scanner.scan_text(page_content)
            if keyword_result.is_suspicious:
                suspicious_elements.append({
                    "type": "content",
                    "warnings": keyword_result.warnings,
                    "risk_level": keyword_result.risk_level,
                    "details": keyword_result.details
                })

        # 4. Overall risk assessment
        risk_level = "safe"
        if warnings or suspicious_elements:
            risk_level = "high" if any(w["level"] == "high" for w in warnings) else "medium"

        return {
            "is_suspicious": bool(warnings or suspicious_elements),
            "risk_level": risk_level,
            "warnings": warnings,
            "suspicious_elements": suspicious_elements,
            "safe_to_proceed": risk_level == "safe"
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