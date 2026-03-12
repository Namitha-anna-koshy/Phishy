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
        raise RuntimeError("ML model or SHAP explainer failed to initialize. Check paths.")


def calculate_vt_intensity(vt_results: dict) -> float:
    """
    Calculates maliciousness score (0.0 - 1.0) using VirusTotal signals.

    KEY DESIGN: vt_ratio uses a power curve (x^0.35) so that even small
    engine ratios produce meaningfully high scores. This correctly handles
    cases where 2 engines flagging vs 16 engines flagging produce very
    different outputs despite both being small absolute ratios.

    Dynamic weights based on reputation availability:

      |reputation| < 100  (unknown domain):
          Engine consensus dominates — it's the only signal we have.
          base = 0.70*vt_ratio + 0.15*rep_norm + 0.15*vt_norm

      |reputation| >= 100 (known domain):
          Historical reputation dominates — accumulated community trust.
          base = 0.20*vt_ratio + 0.65*rep_norm + 0.15*vt_norm

    Additive boosts (each shrinks remaining headroom toward 1.0):
        malicious_count > 3  → +15% headroom  (beyond noise threshold)
        malicious_count > 8  → +40% headroom  (strong multi-engine consensus)
        reputation < -1000   → +25% headroom  (confirmed bad actor history)
        vt_score > 10        → +10% headroom  (high raw VT score)

    Verdict thresholds (applied in analyze_url):
        >= 65%  → MALICIOUS
        >= 45%  → SUSPICIOUS
        < 45%   → CLEAN
        MALICIOUS verdict from VT always floors at 45%
    """
    malicious_count  = vt_results.get("malicious_count", 0)
    suspicious_count = vt_results.get("suspicious_count", 0)
    total_engines    = vt_results.get("total_engines", 1)   # avoid div-by-zero
    reputation       = vt_results.get("reputation", 0)
    vt_score         = vt_results.get("vt_score", 0.0)

    # --- base signals ---
    raw_ratio = (malicious_count + 0.5 * suspicious_count) / total_engines
    vt_ratio  = raw_ratio ** 0.35   # power curve: amplifies low ratios aggressively
    rep_norm  = min(max(-reputation / 2000, 0.0), 1.0)
    vt_norm   = min(max(vt_score / 100, 0.0), 1.0)

    # --- dynamic weights ---
    if abs(reputation) < 100:
        # unknown domain: engine ratio is the primary signal
        base = 0.70 * vt_ratio + 0.15 * rep_norm + 0.15 * vt_norm
    else:
        # known domain: reputation history dominates
        base = 0.20 * vt_ratio + 0.65 * rep_norm + 0.15 * vt_norm

    # --- additive boosts ---
    if malicious_count > 3:
        base = base + 0.15 * (1.0 - base)   # beyond noise, real signal

    if malicious_count > 8:
        base = base + 0.40 * (1.0 - base)   # strong multi-engine consensus

    if reputation < -1000:
        base = base + 0.25 * (1.0 - base)   # confirmed bad actor

    if vt_score > 10:
        base = base + 0.10 * (1.0 - base)   # high raw VT score

    return min(base, 1.0)


def calculate_ml_intensity(ml_results: dict) -> float:
    """
    Calculates maliciousness score (0.0 - 1.0) from SHAP feature impacts.
    Used ONLY when VirusTotal is unavailable or returns an error.

    Formula:
        shap_risk = |sum of negative SHAP values| / |sum of all SHAP values|
        score     = clamp(shap_risk + 0.1 * confidence_score, 0, 1)

    Negative SHAP values push toward malicious classification.
    The higher their proportion, the riskier the URL.
    """
    feature_impacts  = ml_results.get("feature_impacts", {})
    confidence_score = ml_results.get("confidence_score", 0.0)

    values    = list(feature_impacts.values())
    neg_sum   = sum(abs(v) for v in values if v < 0)
    total_sum = sum(abs(v) for v in values)

    shap_risk = (neg_sum / total_sum) if total_sum > 0 else 0.0
    score     = shap_risk + 0.1 * confidence_score

    return min(max(score, 0.0), 1.0)


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

        vt_verdict = vt_results.get("verdict")

        if vt_verdict == "CLEAN":
            # trust explicit clean verdict from VT
            final_verdict  = "CLEAN"
            risk_intensity = 0.0
            source         = "VirusTotal"

        elif vt_verdict in ("ERROR", "CONNECTION_FAILED", "NOT_FOUND") or not vt_verdict:
            # VT unavailable — fall back entirely to ML SHAP score
            ml_score       = calculate_ml_intensity(ml_results)
            risk_intensity = round(ml_score * 100, 2)
            final_verdict  = ml_results.get("verdict", "CLEAN")
            source         = "Model"

        else:
            # VT returned MALICIOUS or SUSPICIOUS — use VT-based formula
            vt_score       = calculate_vt_intensity(vt_results)
            risk_intensity = round(vt_score * 100, 2)

            # floor: if VT explicitly says MALICIOUS, bar never drops below 45%
            # even for domains with sparse signals (e.g. newly registered typosquats)
            if vt_verdict == "MALICIOUS":
                risk_intensity = max(risk_intensity, 45.0)

            # safety-net 1: strong positive reputation + zero flags = clean
            if vt_results.get("reputation", 0) > 100 and vt_results.get("malicious_count", 0) == 0:
                final_verdict  = "CLEAN"
                risk_intensity = 0.0

            # safety-net 2: highly trusted domain with 1-2 rogue engine flags
            elif vt_results.get("reputation", 0) > 500 and vt_results.get("malicious_count", 0) <= 2:
                final_verdict  = "CLEAN"
                risk_intensity = min(risk_intensity, 5.0)

            # verdict thresholds (tuned against known typosquat test cases)
            elif risk_intensity >= 65:
                final_verdict = "MALICIOUS"
            elif risk_intensity >= 45:
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