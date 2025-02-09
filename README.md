# CyberCTRL Backend

FastAPI-based security scanning backend for the CyberCTRL Chrome extension.

## Features
- 🔒 API endpoint security validation
- 🔍 Domain verification system
- 📊 Trust score calculation
- ⚡ Async request processing

## Tech Stack
- FastAPI
- Python 3.11+
- Pydantic
- aiohttp
- uvicorn

## Installation
bash
Create virtual environment
python -m venv venv
source venv/bin/activate # or venv\Scripts\activate on Windows
Install dependencies
pip install -r requirements.txt
Start the server
./run.sh # or uvicorn main:app --reload --port 8001
Structure
hacknyu-backend/
├── main.py # FastAPI application
├── requirements.txt # Python dependencies
├── run.sh # Server startup script
├── services/ # Core services
│ ├── api_scanner.py
│ └── code_scanner.py
├── schemas/ # Data models
│ ├── security.py
│ └── package.py
└── utils/ # Utilities
└── constants.py

## API Endpoints
- POST `/api/v1/scan/api` - Scan API endpoints
- POST `/api/v1/scan-code` - Analyze code snippets
- GET `/health` - Server health check

## Environment Setup
Create a `.env` file:
PYTHONPATH=/path/to/hacknyu-backend

## Development
1. Start the server in development mode:
bash
uvicorn main:app --reload --port 8001
2. API documentation available at:
   - Swagger UI: http://localhost:8001/docs
   - ReDoc: http://localhost:8001/redoc
