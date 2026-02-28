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
    Performs hybrid analysis with a safety net for high-reputation domains.
    Ensures local ML false positives don't override global safe status.
    """
    try:
        # 1. External Scan (VirusTotal)
        vt_results = get_virus_total_report(request.url)
        
        # 2. Local ML Scan (LightGBM + SHAP)
        ml_results = get_ml_prediction(request.url)
        
        # 3. Calculate Numerical Risk Intensity (0-100%)
        risk_intensity = calculate_intensity(vt_results, ml_results)
        
        # 4. Final Verdict Logic with Safety Net
        final_verdict = "CLEAN"
        
        # Safety Check: If VT reputation is high and malicious count is 0, it's CLEAN
        # even if the ML model is overconfident
        is_highly_reputable = vt_results.get("reputation", 0) > 100
        has_zero_vt_flags = vt_results.get("malicious_count", 0) == 0

        if is_highly_reputable and has_zero_vt_flags:
            final_verdict = "CLEAN"
        # Otherwise, follow the standard intensity-based thresholding
        elif risk_intensity >= 75:
            final_verdict = "MALICIOUS"
        elif risk_intensity >= 40:
            final_verdict = "SUSPICIOUS"
        else:
            final_verdict = "CLEAN"

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
        raise HTTPException(
            status_code=500,
            detail=f"Internal Analysis Failure: {str(error)}"
        ) from error