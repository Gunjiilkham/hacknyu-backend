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
    allow_origins=["*"],  # In production, replace with specific origins
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

@app.get("/")
async def root():
    return {
        "message": "Welcome to Silent Guardian API",
        "version": "1.0.0",
        "endpoints": {
            "package_check": "/api/v1/check-package",
            "code_scan": "/api/v1/scan-code",
            "api_check": "/api/v1/check-api-url"
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

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 