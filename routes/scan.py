from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from services.code_scanner import CodeScanner
from typing import Dict, Any
import logging

router = APIRouter()

logger = logging.getLogger(__name__)

class ExtensionScanRequest(BaseModel):
    data: Dict[str, Any]

@router.post("/extension/scan")
async def scan_extension(request: ExtensionScanRequest):
    try:
        # Ensure 'code' is present in the request data
        if 'code' not in request.data:
            raise HTTPException(status_code=400, detail="Missing 'code' in request data.")
        
        code = request.data['code']
        if code is None or not isinstance(code, str):
            raise HTTPException(status_code=400, detail="'code' must be a non-empty string.")
        
        scanner = CodeScanner()
        result = await scanner.scan_code(code)
        
        # Ensure `trustScore` is present in the response
        if "trustScore" not in result:
            result["trustScore"] = 50  # Default score if missing
        
        return result
    except Exception as e:
        print(f"ERROR in scan_extension: {e}")
        raise HTTPException(status_code=500, detail=str(e))

class CodeScanRequest(BaseModel):
    code: str

@router.post("/scan-code")
async def scan_code(request: CodeScanRequest):
    try:
        scanner = CodeScanner()
        return await scanner.scan_code(request.code)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class WebScanRequest(BaseModel):
    url: str

@router.post("/scan-webpage")
async def scan_webpage(request: WebScanRequest):
    try:
        logger.info(f"Scanning webpage: {request.url}")
        scanner = CodeScanner()
        result = await scanner.scan_webpage(request.url)
        logger.info(f"Scan result: {result}")
        return result
    except Exception as e:
        logger.error(f"Error scanning webpage: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

class KeywordScanRequest(BaseModel):
    text: str

@router.post("/scan-keywords")
async def scan_keywords(request: KeywordScanRequest):
    try:
        scanner = CodeScanner()
        return await scanner.scan_code(request.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e)) 