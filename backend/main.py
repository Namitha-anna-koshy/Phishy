from fastapi import FastAPI
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from services.vt_service import get_virus_total_report
from services.ml_service import get_ml_prediction

app = FastAPI(title="Phishy Backend - Hybrid Engine")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class URLRequest(BaseModel):
    url: str

@app.post("/analyze")
async def analyze_url(request: URLRequest) -> dict:
    """
    Hybrid analysis: Runs VirusTotal (Global Intel) and LightGBM (Local ML) 
    parallelly to provide a comprehensive threat report.
    """
    # 1. External Scan (VirusTotal)
    vt_results = get_virus_total_report(request.url)
    
    # 2. Local ML Scan (LightGBM)
    ml_results = get_ml_prediction(request.url)
    
    # 3. Decision Logic (Condition Check)
    # If either engine flags it as Malicious, the final verdict is Malicious.
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