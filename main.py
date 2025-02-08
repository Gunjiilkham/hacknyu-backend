from fastapi import FastAPI
import uvicorn

app = FastAPI(
    title="Silent Guardian API",
    description="Backend API for Silent Guardian security scanner",
    version="1.0.0"
)

@app.get("/")
async def root():
    return {"message": "Welcome to Silent Guardian API"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True) 