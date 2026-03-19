"""
Main entry point for the Phishy Backend API.
Handles URL analysis by orchestrating global threat intelligence
and communicating with the dedicated ML Inference Service.
"""

import asyncio
import httpx  # Used to talk to the model_service container

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from services.vt_service import get_virus_total_report

app = FastAPI(
    title="Phishy - Hybrid Threat Detection Engine",
    description="API for detecting phishing URLs using VirusTotal and LightGBM.",
    version="1.1.0",
)

# Enable CORS so your Nginx frontend can talk to this backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str = Field(..., example="https://phish-site.example.com")

@app.on_event("startup")
def startup_checks() -> None:
    """
    Since the model is in another container, we no longer check for it here.
    """
    pass

async def fetch_ml_prediction(url: str) -> dict:
    """Sends the URL to the dedicated model_service container for prediction."""
    try:
        # We use the container name "model_service" as the domain name
        async with httpx.AsyncClient() as client:
            response = await client.post(
                "http://model_service:8000/predict",
                json={"url": url},
                timeout=10.0 
            )
            response.raise_for_status()
            return response.json()
    except Exception as e:
        print(f"Failed to reach ML service: {e}")
        return {
            "verdict": "ERROR", 
            "feature_impacts": {}, 
            "confidence_score": 0.0,
            "error": str(e)
        }

def calculate_vt_intensity(vt_results: dict) -> float:
    malicious_count  = vt_results.get("malicious_count", 0)
    suspicious_count = vt_results.get("suspicious_count", 0)
    total_engines    = vt_results.get("total_engines", 1)   
    reputation       = vt_results.get("reputation", 0)
    vt_score         = vt_results.get("vt_score", 0.0)

    raw_ratio = (malicious_count + 0.5 * suspicious_count) / total_engines
    vt_ratio  = raw_ratio ** 0.35   
    rep_norm  = min(max(-reputation / 2000, 0.0), 1.0)
    vt_norm   = min(max(vt_score / 100, 0.0), 1.0)

    if abs(reputation) < 100:
        base = 0.70 * vt_ratio + 0.15 * rep_norm + 0.15 * vt_norm
    else:
        base = 0.20 * vt_ratio + 0.65 * rep_norm + 0.15 * vt_norm

    if malicious_count > 3: base = base + 0.15 * (1.0 - base)   
    if malicious_count > 8: base = base + 0.40 * (1.0 - base)   
    if reputation < -1000: base = base + 0.25 * (1.0 - base)   
    if vt_score > 10: base = base + 0.10 * (1.0 - base)   

    return min(base, 1.0)


def calculate_ml_intensity(ml_results: dict) -> float:
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
    return {
        "status": "Phishy Engine Online",
        "active_branch": "32-integrate-shap-to-the-backend",
        "ml_engine": "Microservice Architecture Ready"
    }


@app.post("/analyze")
async def analyze_url(request: URLRequest) -> dict:
    try:
        vt_task = asyncio.to_thread(get_virus_total_report, request.url)
        ml_task = fetch_ml_prediction(request.url) 
        
        vt_results, ml_results = await asyncio.gather(vt_task, ml_task)

        vt_verdict = vt_results.get("verdict")

        if vt_verdict == "CLEAN":
            final_verdict  = "CLEAN"
            risk_intensity = 0.0
            source         = "VirusTotal"

        elif vt_verdict in ("ERROR", "CONNECTION_FAILED", "NOT_FOUND") or not vt_verdict:
            ml_score       = calculate_ml_intensity(ml_results)
            risk_intensity = round(ml_score * 100, 2)
            final_verdict  = ml_results.get("verdict", "CLEAN")
            source         = "Model"

        else:
            vt_score       = calculate_vt_intensity(vt_results)
            risk_intensity = round(vt_score * 100, 2)

            if vt_verdict == "MALICIOUS":
                risk_intensity = max(risk_intensity, 45.0)

            if vt_results.get("reputation", 0) > 100 and vt_results.get("malicious_count", 0) == 0:
                final_verdict  = "CLEAN"
                risk_intensity = 0.0

            elif vt_results.get("reputation", 0) > 500 and vt_results.get("malicious_count", 0) <= 2:
                final_verdict  = "CLEAN"
                risk_intensity = min(risk_intensity, 5.0)

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