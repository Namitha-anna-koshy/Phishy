"""
ML Service module for URL feature extraction, phishing prediction, and SHAP analysis.
This module integrates a LightGBM model and SHAP explainer for local intelligence.
"""

import os
import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import shap

# Dynamic path handling to find the model relative to this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "..", "model.pkl")

def load_resources():
    """
    Safely loads the LightGBM model and initializes the SHAP explainer.
    """
    try:
        model = joblib.load(MODEL_PATH)
        # TreeExplainer is highly optimized for LightGBM models
        explainer = shap.TreeExplainer(model)
        return model, explainer
    except (FileNotFoundError, IOError, Exception) as error:
        print(f"Critical Error: Could not load ML resources at {MODEL_PATH}: {error}")
        return None, None

# Global instances initialized at startup for efficiency
LGBM_MODEL, SHAP_EXPLAINER = load_resources()

def extract_url_features(url: str) -> pd.DataFrame:
    """
    Extracts numerical features from a URL string for model inference.
    """
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "is_https": 1 if url.startswith("https") else 0,
    }
    return pd.DataFrame([features])

def get_ml_prediction(url: str) -> dict:
    """
    Performs inference and SHAP explanation on a URL.
    
    Returns:
        dict: Contains verdict, raw confidence, and feature-level impacts.
    """
    if LGBM_MODEL is None or SHAP_EXPLAINER is None:
        return {
            "verdict": "ERROR",
            "confidence_score": 0.0,
            "message": "ML Engine or Explainer not loaded"
        }

    features_df = extract_url_features(url)
    
    try:
        # 1. Get Probability Score
        prob = float(LGBM_MODEL.predict_proba(features_df)[0][1])
        
        # 2. Compute SHAP values for the specific prediction
        # shap_values[1] represents the 'Malicious' class contributions
        shap_values = SHAP_EXPLAINER.shap_values(features_df)
        contributions = shap_values[1][0] if isinstance(shap_values, list) else shap_values[0]

        # Map feature names to their respective impact scores
        explanation = {
            name: round(float(val), 4) 
            for name, val in zip(features_df.columns, contributions)
        }

        # 3. Verdict Logic
        if prob > 0.8:
            label = "MALICIOUS"
        elif prob > 0.4:
            label = "SUSPICIOUS"
        else:
            label = "CLEAN"

        return {
            "verdict": label,
            "confidence_score": round(prob, 4),
            "feature_impacts": explanation,
            "engine": "LightGBM + SHAP Explainer"
        }

    except (AttributeError, ValueError, IndexError, Exception) as error:
        return {
            "verdict": "ERROR",
            "confidence_score": 0.0,
            "message": f"Analysis failed: {str(error)}"
        }