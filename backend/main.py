"""
Main entry point for the Phishy Backend API.
Handles URL analysis by orchestrating global threat intelligence
and local machine learning inference with SHAP explainability.
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from services.vt_service import get_virus_total_report
from services.ml_service import get_ml_prediction, LGBM_MODEL, SHAP_EXPLAINER

app = FastAPI(
    title="Phishy - Hybrid Threat Detection Engine",
    description="API for detecting phishing URLs using VirusTotal and LightGBM.",
    version="1.1.0",
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

@app.on_event("startup")
def startup_checks() -> None:
    """Validate that the LightGBM model and SHAP explainer loaded properly at startup."""
    if LGBM_MODEL is None or SHAP_EXPLAINER is None:
        # Critical failure: prevents the server from starting with broken ML components
        raise RuntimeError("ML model or SHAP explainer failed to initialize. Check paths.")

def calculate_intensity(vt_results: dict, ml_results: dict) -> float:
    """
    Calculates a 0-100% risk intensity score.
    Logic: (VirusTotal Detections * 0.6) + (ML Confidence * 0.4)
    """
    # VT Intensity: Normalized by number of engines flagging the URL
    vt_ratio = 0.0
    malicious_count = vt_results.get("malicious_count", 0)
    if vt_results.get("total_engines", 0) > 0:
        # 5+ engines usually indicates a high-confidence threat
        vt_ratio = min(malicious_count / 5, 1.0)

    # ML Intensity: Raw probability from the LightGBM model
    ml_prob = ml_results.get("confidence_score", 0.0)

    # Weighted aggregate score
    intensity = (vt_ratio * 0.6) + (ml_prob * 0.4)
    return round(intensity * 100, 2)

@app.get("/")
def health_check() -> dict:
    """Verifies the API status and active development branch."""
    return {
        "status": "Phishy Engine Online",
        "active_branch": "32-integrate-shap-to-the-backend",
        "ml_engine": "LightGBM + SHAP Ready"
    }

@app.post("/analyze")
async def analyze_url(request: URLRequest) -> dict:
    """
    Performs hybrid analysis by running VirusTotal and ML scans.
    Returns a unified verdict, intensity score, and SHAP feature impacts.
    """
    try:
        # 1. External Scan (VirusTotal)
        vt_results = get_virus_total_report(request.url)
        
        # 2. Local ML Scan (LightGBM + SHAP)
        ml_results = get_ml_prediction(request.url)
        
        # 3. Calculate Numerical Risk Intensity
        risk_intensity = calculate_intensity(vt_results, ml_results)
        
        # 4. Final Verdict Logic
        # Malicious if either engine has a high-confidence threat detection
        final_verdict = "CLEAN"
        if vt_results.get("verdict") == "MALICIOUS" or ml_results.get("verdict") == "MALICIOUS":
            final_verdict = "MALICIOUS"
        elif vt_results.get("verdict") == "SUSPICIOUS" or ml_results.get("verdict") == "SUSPICIOUS":
            final_verdict = "SUSPICIOUS"

        return {
            "url": request.url,
            "final_verdict": final_verdict,
            "malicious_intensity": f"{risk_intensity}%",
            "hybrid_report": {
                "global_threat_intel": vt_results,
                "local_ml_engine": ml_results
            },
            "engine_status": "Success: Hybrid explainable analysis complete."
        }
    except Exception as error:
        # Explicit re-raising with exception chaining for better debugging
        raise HTTPException(
            status_code=500,
            detail=f"Internal Analysis Failure: {str(error)}"
        ) from error