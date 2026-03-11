"""
Main entry point for the Phishy Backend API.
Handles URL analysis by orchestrating global threat intelligence
and local machine learning inference with SHAP explainability.
"""

import os
import asyncio

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

# serve the frontend static assets (HTML/CSS/JS) from the `frontend/` folder
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, RedirectResponse

# determine the absolute path to the frontend directory (relative to this file)
FRONTEND_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "frontend")
)

# mount the whole directory at /static
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

# root path redirects to the main web page
@app.get("/")
def root_redirect():
    return RedirectResponse(url="/web.html")

# explicit route to return the HTML (useful if redirect fails)
@app.get("/web.html", response_class=FileResponse)
def serve_web():
    return FileResponse(os.path.join(FRONTEND_DIR, "web.html"))

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

@app.get("/health")
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
    Executes the VT and ML scans concurrently and chooses the final verdict
    based on available information (VT overrides when clean, ML only when
    VT unavailable, hybrid otherwise).
    """
    try:
        # dispatch both scans in parallel threads to reduce latency
        vt_task = asyncio.to_thread(get_virus_total_report, request.url)
        ml_task = asyncio.to_thread(get_ml_prediction, request.url)
        vt_results, ml_results = await asyncio.gather(vt_task, ml_task)

        # determine output according to available data
        vt_verdict = vt_results.get("verdict")
        # compute a score from the latest engine counts (ignore cached vt_score)
        total_engines = vt_results.get("total_engines", 0)
        malicious_count = vt_results.get("malicious_count", 0)
        if total_engines > 0:
            vt_score = round((malicious_count / total_engines) * 100, 2)
        else:
            vt_score = 0.0
        if vt_verdict == "CLEAN":
            # trust explicit clean from the API
            final_verdict = "CLEAN"
            risk_intensity = 0.0
            source = "VirusTotal"
        elif vt_verdict in ("ERROR", "CONNECTION_FAILED", "NOT_FOUND") or not vt_verdict:
            # fallback to ML when VT can't provide a verdict
            final_verdict = ml_results.get("verdict", "CLEAN")
            risk_intensity = float(ml_results.get("confidence_score", 0.0)) * 100
            source = "Model"
        else:
            # VT returned suspicious or malicious
            if vt_score > 0:
                # use the API-derived score directly when available
                risk_intensity = vt_score
            else:
                # otherwise fallback to original hybrid formula
                risk_intensity = calculate_intensity(vt_results, ml_results)

            # boost completely malicious results so they're always high-risk
            if vt_verdict == "MALICIOUS":
                risk_intensity = max(risk_intensity, 80.0)

            # safety-net: high reputation + zero flags = clean
            if vt_results.get("reputation", 0) > 100 and vt_results.get("malicious_count", 0) == 0:
                final_verdict = "CLEAN"
            elif risk_intensity >= 75:
                final_verdict = "MALICIOUS"
            elif risk_intensity >= 40:
                final_verdict = "SUSPICIOUS"
            else:
                final_verdict = "CLEAN"
            source = "Hybrid"

        return {
            "url": request.url,
            "final_verdict": final_verdict,
            "malicious_intensity": f"{risk_intensity}%",
            "source": source,
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