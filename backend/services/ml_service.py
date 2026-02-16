import joblib
import pandas as pd
import re
from urllib.parse import urlparse

# Load the model (ensure the file is in backend/models/)
MODEL_PATH = r'C:\Users\Namitha Anna Koshy\Documents\HONORS\PROJECT\Phishy\Phishy\model\url_phishing_lgbm_model.pkl'

try:
    # Use joblib to load your trained LightGBM model
    lgbm_model = joblib.load(MODEL_PATH)
except Exception as e:
    print(f"Critical Error: Could not load ML model: {e}")
    lgbm_model = None

def extract_url_features(url: str) -> pd.DataFrame:
    """
    Extracts features from a URL string to match the model's training schema.
    Ensure these match exactly what you used in your Task 3 Notebook.
    """
    parsed = urlparse(url)
    hostname = parsed.netloc
    
    features = {
        "url_length": len(url),
        "hostname_length": len(hostname),
        "num_dots": url.count('.'),
        "num_hyphens": url.count('-'),
        "is_ip": 1 if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) else 0,
        "is_https": 1 if url.startswith("https") else 0,
        # Add additional features here to match your specific model columns
    }
    return pd.DataFrame([features])

def get_ml_prediction(url: str) -> dict:
    """
    Runs inference using the LightGBM model.
    """
    if lgbm_model is None:
        return {"status": "error", "message": "Model not loaded"}

    features_df = extract_url_features(url)
    
    # Get probability of being malicious (assuming class 1 is phishing)
    prob = lgbm_model.predict_proba(features_df)[0][1]
    
    # Define thresholds for results
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