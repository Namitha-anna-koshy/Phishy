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
    version="1.0.0",
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
    return {"status": "Phishy Engine Online", "active_branch": "7-threat-intelligence"}


@app.post("/analyze")
async def analyze_url(request: URLRequest) -> dict:
    """
    Performs hybrid analysis by running VirusTotal and ML scans in parallel.
    Aggregates results to provide a final threat verdict.
    """
    try:
        # 1. External Scan (VirusTotal)
        vt_results = get_virus_total_report(request.url)
        
        # 2. Local ML Scan (LightGBM)
        ml_results = get_ml_prediction(request.url)
        
        # 3. Decision Logic
        final_verdict = "CLEAN"
        if vt_results.get("verdict") == "MALICIOUS" or ml_results.get("verdict") == "MALICIOUS":
            final_verdict = "MALICIOUS"
        elif vt_results.get("verdict") == "SUSPICIOUS" or ml_results.get("verdict") == "SUSPICIOUS":
            final_verdict = "SUSPICIOUS"

        return {
            "url": request.url,
            "final_verdict": final_verdict,
            "hybrid_report": {
                "global_threat_intel": vt_results,
                "local_ml_engine": ml_results
            },
            "engine_logs": "Analysis completed using Hybrid (VT + LightGBM) pipeline."
        }
    except Exception as error:
        # Now uses the top-level import and exception chaining correctly
        raise HTTPException(
            status_code=500,
            detail=f"Internal Analysis Failure: {str(error)}"
        ) from error