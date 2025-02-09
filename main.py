from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from typing import List, Dict, Optional
import logging
from fastapi.responses import JSONResponse
import requests  # for making HTTP requests
from urllib.parse import urlparse
from enum import Enum
from pydantic import BaseModel
from routes import scanner

from schemas.package import PackageCheck
from schemas.security import SecurityScanResult
from services.package_scanner import PackageScanner
from services.code_scanner import CodeScanner
from services.api_scanner import APIScanner
from services.keyword_scanner import KeywordScanner

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Schema definitions
class RiskLevel(str, Enum):
    SAFE = "safe"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityRating(BaseModel):
    score: int
    risk_level: RiskLevel
    confidence: int

class SecurityScanResult(BaseModel):
    is_suspicious: bool
    risk_level: RiskLevel
    rating: SecurityRating
    warnings: List[str]
    details: Dict[str, str]

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
            content={"detail": str(e)}
        )

# Initialize services
package_scanner = PackageScanner()
code_scanner = CodeScanner()
api_scanner = APIScanner()
keyword_scanner = KeywordScanner()

# Include routers
app.include_router(scanner.router, prefix="/api/v1")

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

@app.post("/api/v1/scan-code", response_model=SecurityScanResult)
async def scan_code(request: Request):
    body = await request.json()
    code = body.get("code")

    if not code or not isinstance(code, str):
        raise HTTPException(status_code=400, detail="Code is required and must be a valid string.")

    try:
        result = await code_scanner.scan_code(code)

        # Ensure `trustScore` is present
        if "trustScore" not in result:
            result["trustScore"] = 50  # Default if missing

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/check-api-url")
async def check_api_url(request: Request):
    body = await request.json()
    url = body.get("url")
    
    if not url or not isinstance(url, str):
        raise HTTPException(status_code=400, detail="Invalid input: URL must be a non-empty string.")

    try:
        result = await api_scanner.check_url(url)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class WebScanResult(BaseModel):
    trustScore: int
    isSuspicious: bool
    alerts: List[str]
    details: Dict[str, str]

@app.post("/api/v1/scan-webpage", response_model=WebScanResult)
async def scan_webpage(request: Request):
    try:
        body = await request.json()
        url = body.get("url")

        if not url or not isinstance(url, str):
            raise HTTPException(status_code=400, detail="Invalid input: URL must be a valid string.")

        # Perform the scan
        result = await code_scanner.scan_webpage(url)

        # Ensure `trustScore` is present in all responses
        if "trustScore" not in result:
            result["trustScore"] = 50  # Default score if missing
        
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/v1/extension/scan")
async def scan_for_extension(request: Request):
    try:
        data = await request.json()
        
        # Validate required fields
        if "url" not in data:
            raise HTTPException(status_code=400, detail="Missing required field: 'url'")
        
        url = data.get("url")
        if not url or not isinstance(url, str):
            raise HTTPException(status_code=400, detail="Invalid input: 'url' must be a valid string.")
        
        # Optional fields
        page_content = data.get("content", "")
        scripts = data.get("scripts", [])

        # Perform the scan
        trust_points = 100
        warnings = []
        risk_factors = []

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
            if 'torrent' in page_content.lower() or 'crack' in page_content.lower():
                trust_points -= 40
                warnings.append("⚠️ Piracy content detected")

        # Script checks
        for script in scripts:
            # Check for dangerous patterns
            dangerous_patterns = {
                'eval(': 'Dynamic code execution',
                'document.write(': 'Unsafe DOM manipulation',
                'api_key': 'Exposed credentials',
                # Add more patterns as needed
            }
            for pattern, reason in dangerous_patterns.items():
                if pattern in script:
                    trust_points -= 20
                    warnings.append(f"⚠️ Dangerous: {reason}")
                    risk_factors.append(f"dangerous_{pattern}")

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

@app.post("/api/v1/scan-keywords", response_model=SecurityScanResult)
async def scan_keywords(request: Request):
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
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True) 