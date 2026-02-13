from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from services.vt_service import get_virus_total_report

app = FastAPI(title="Phishy Backend - Milestone 4")

# Enable CORS so the Next.js frontend can communicate with this API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.get("/")
def home():
    return {"status": "Phishy Engine Online", "active_branch": "7-threat-intelligence"}

@app.post("/analyze")
async def analyze_url(request: URLRequest):
    # Fetch data from the VirusTotal service
    vt_results = get_virus_total_report(request.url)
    
    return {
        "url": request.url,
        "verdict": vt_results.get("verdict"),
        "threat_intel": vt_results,
        "engine_logs": "Analysis completed via VirusTotal API."
    }