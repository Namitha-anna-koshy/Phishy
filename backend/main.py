"""
Main entry point for the Phishy Backend API.
Handles URL analysis by orchestrating global threat intelligence 
and local machine learning inference.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from services.vt_service import get_virus_total_report
from services.ml_service import get_ml_prediction

app = FastAPI(
    title="Phishy - Hybrid Threat Detection Engine",
    description="API for detecting phishing URLs using VirusTotal and LightGBM.",
    version="1.0.0"
)

# Enable CORS for frontend communication (Next.js)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    """Schema for incoming URL analysis requests."""
    url: str = Field(..., example="https://phish-site.example.com")

@app.get("/")
def health_check() -> dict:
    """Verifies the API status and active development branch."""
    return {
        "status": "Phishy Engine Online",
        "active_branch": "7-threat-intelligence"
    }

@app.post("/analyze")
async def analyze_url(request: URLRequest) -> dict:
    """
    Performs hybrid analysis by running VirusTotal and ML scans in parallel.
    Aggregates results to provide a final threat verdict.
    """
    try:
        # 1. Fetch Global Intelligence (VirusTotal)
        vt_results = get_virus_total_report(request.url)
        
        # 2. Fetch Local Intelligence (LightGBM)
        ml_results = get_ml_prediction(request.url)
        
        # 3. Decision Logic: Aggregate verdicts
        final_verdict = "CLEAN"
        if vt_results.get("verdict") == "MALICIOUS" or ml_results.get("verdict") == "MALICIOUS":
            final_verdict = "MALICIOUS"
        elif ml_results.get("verdict") == "SUSPICIOUS":
            final_verdict = "SUSPICIOUS"

        return {
            "url": request.url,
            "final_verdict": final_verdict,
            "hybrid_report": {
                "global_threat_intel": vt_results,
                "local_ml_engine": ml_results
            },
            "engine_status": "Success: Dual-layered analysis complete."
        }
        
    except Exception as error:
        # Catch-all for unexpected engine failures to prevent 500 errors
        raise HTTPException(
            status_code=500, 
            detail=f"Internal Analysis Failure: {str(error)}"
        )