"""
ML Service module for URL feature extraction and phishing prediction.
This module integrates a LightGBM model to provide local intelligence.
"""

import re
from urllib.parse import urlparse
import joblib
import pandas as pd
import os

# This gets the directory where ml_service.py is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Move up one level if the model is in the parent 'backend' folder
MODEL_PATH = os.path.join(BASE_DIR, "..", "model.pkl")

def load_model():
    """
    Safely loads the LightGBM model from the specified path.
    """
    try:
        return joblib.load(MODEL_PATH)
    except (FileNotFoundError, IOError) as error:
        print(f"Critical Error: Could not load ML model at {MODEL_PATH}: {error}")
        return None

# Global model instance for efficiency
LGBM_MODEL = load_model()

def extract_url_features(url: str) -> pd.DataFrame:
    """
    Extracts numerical features from a URL string for model inference.
    
    Args:
        url (str): The raw URL string to analyze.
        
    Returns:
        pd.DataFrame: A single-row DataFrame containing extracted features.
    """
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        #"is_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "is_https": 1 if url.startswith("https") else 0,
    }
    return pd.DataFrame([features])

def get_ml_prediction(url: str) -> dict:
    """
    Performs inference on a URL and returns a standardized verdict.
    
    Args:
        url (str): The URL to analyze.
        
    Returns:
        dict: A dictionary containing the verdict and confidence score.
    """
    if LGBM_MODEL is None:
        return {
            "verdict": "ERROR",
            "confidence_score": 0.0,
            "message": "Model not loaded"
        }

    features_df = extract_url_features(url)
    
    # Get probability for the positive class (phishing)
    # Standard LightGBM predict_proba returns [prob_class_0, prob_class_1]
    try:
        prob = LGBM_MODEL.predict_proba(features_df)[0][1]
    except (AttributeError, ValueError, IndexError) as error:
        return {
            "verdict": "ERROR",
            "confidence_score": 0.0,
            "message": f"Inference failed: {str(error)}"
        }
    
    # Verdict thresholding logic
    if prob > 0.8:
        label = "MALICIOUS"
    elif prob > 0.4:
        label = "SUSPICIOUS"
    else:
        label = "CLEAN"

    return {
        "verdict": label,
        "confidence_score": round(float(prob), 4),
        "engine": "LightGBM Classifier"
    }