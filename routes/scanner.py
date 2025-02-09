from fastapi import APIRouter, HTTPException
from schemas.security import SecurityScanResult
from services.api_scanner import APIScanner
from typing import Dict

router = APIRouter()
scanner = APIScanner()

@router.post("/scan/api", response_model=SecurityScanResult)
async def scan_api(data: Dict[str, str]):
    """
    Endpoint to scan an API URL for security issues
    """
    if "url" not in data:
        raise HTTPException(status_code=400, detail="URL is required")
    
    try:
        result = await scanner.check_url(data["url"])
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 