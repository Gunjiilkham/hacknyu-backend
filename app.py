from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from services.code_scanner import CodeScanner
from pydantic import BaseModel
from typing import List, Dict, Any

app = FastAPI()

# Initialize the code scanner
scanner = CodeScanner()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["chrome-extension://*"],  # Allow Chrome extensions
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class ScanRequest(BaseModel):
    url: str
    content: str
    scripts: List[Dict[str, str]]

@app.get("/health")
async def health_check():
    return {"status": "ok"}

@app.post("/extension/scan")
async def scan_content(request: ScanRequest):
    try:
        # Analyze the content using CodeScanner
        result = await scanner.analyze_code(request.content)
        
        # Also analyze any scripts
        for script in request.scripts:
            script_result = await scanner.analyze_code(script.get("content", ""))
            result.alerts.extend(script_result.alerts)
            if hasattr(result, 'trustScore') and hasattr(script_result, 'trustScore'):
                result.trustScore = min(result.trustScore, script_result.trustScore)
        
        return result
        
    except Exception as e:
        print(f"Error in scan_content: {str(e)}")
        return {
            "trustScore": 0,
            "alerts": [f"Error analyzing content: {str(e)}"],
            "isSuspicious": True,
            "details": {"error": str(e)}
        }

@app.get("/api/v1/scan-webpage")
async def scan_webpage(url: str):
    try:
        # Use the scanner to analyze the webpage
        result = await scanner.scan_webpage(url)
        return result
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error scanning webpage: {str(e)}"
        ) 