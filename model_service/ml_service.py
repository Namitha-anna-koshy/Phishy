"""
ML Service module for URL feature extraction, phishing prediction, and SHAP analysis.
Aligned with LightGBM native model trained on PhiUSIIL dataset (21 URL-only features).
"""

import os
import re
import math
from urllib.parse import urlparse

import joblib
import pandas as pd
import shap

# ── Model loading ─────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
META_PATH  = os.path.join(BASE_DIR, "model_meta.pkl")

# These must exactly match the column names used during training
URL_FEATURES = [
    "URLLength",
    "URLSimilarityIndex",
    "CharContinuationRate",
    "TLDLegitimateProb",
    "URLCharProb",
    "TLDLength",
    "NoOfSubDomain",
    "HasObfuscation",
    "NoOfObfuscatedChar",
    "ObfuscationRatio",
    "LetterRatioInURL",
    "NoOfDegitsInURL",
    "DegitRatioInURL",
    "NoOfEqualsInURL",
    "NoOfQMarkInURL",
    "NoOfAmpersandInURL",
    "NoOfOtherSpecialCharsInURL",
    "SpacialCharRatioInURL",
    "IsHTTPS",
    "IsDomainIP",
    "DomainLength",
]

# Known legitimate TLDs and their approximate legitimacy probabilities
TLD_LEGIT_PROB = {
    "com": 0.52, "org": 0.08, "net": 0.05, "edu": 0.03,
    "gov": 0.02, "uk":  0.03, "de":  0.03, "au":  0.02,
    "ca":  0.02, "fr":  0.02, "jp":  0.02, "io":  0.01,
    "co":  0.01, "info":0.005,"biz": 0.003,
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "club", "online", "site", "web",
    "live", "stream", "gq", "ml", "tk", "cf", "ga"
}


def load_resources():
    """
    Loads LightGBM model, metadata, and initializes SHAP TreeExplainer.
    """
    try:
        model    = joblib.load(MODEL_PATH)
        meta     = joblib.load(META_PATH) if os.path.exists(META_PATH) else {}
        explainer = shap.TreeExplainer(model)
        threshold = meta.get("threshold", 0.35)
        print(f"ML model loaded | threshold={threshold} | features={len(URL_FEATURES)}")
        return model, explainer, threshold
    except (FileNotFoundError, IOError, Exception) as error:
        print(f"Critical Error: Could not load ML resources: {error}")
        return None, None, 0.35


LGBM_MODEL, SHAP_EXPLAINER, MODEL_THRESHOLD = load_resources()


def _get_tld(hostname: str) -> str:
    """Extracts TLD from hostname."""
    parts = hostname.lower().split(".")
    return parts[-1] if parts else ""


def _is_ip(hostname: str) -> int:
    """Checks if hostname is a raw IP address."""
    import socket
    try:
        socket.inet_aton(hostname)
        return 1
    except socket.error:
        return 0


def _url_char_prob(url: str) -> float:
    """
    Estimates character probability score.
    Legitimate URLs tend to use common characters.
    Lower score = more unusual character distribution = suspicious.
    """
    common = set("abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;=%")
    if not url:
        return 0.0
    return round(sum(1 for c in url.lower() if c in common) / len(url), 6)


def _char_continuation_rate(url: str) -> float:
    """
    Measures how often consecutive characters are the same type (letter/digit).
    High rate = natural language = legitimate.
    Low rate = mixed random chars = suspicious.
    """
    if len(url) < 2:
        return 0.0
    same = sum(
        1 for i in range(len(url) - 1)
        if url[i].isalpha() == url[i+1].isalpha()
    )
    return round(same / (len(url) - 1), 6)


def _url_similarity_index(url: str) -> float:
    """
    Checks if URL contains brand names from known legitimate domains.
    High score = contains known brand = suspicious if domain doesn't match.
    Simple lexical check — no external API needed.
    """
    brands = [
        "google", "facebook", "apple", "microsoft", "amazon",
        "paypal", "netflix", "instagram", "twitter", "linkedin",
        "banking", "secure", "account", "login", "verify", "update"
    ]
    url_lower = url.lower()
    matches   = sum(1 for b in brands if b in url_lower)
    return round(min(matches / len(brands) * 100, 100), 4)


def extract_url_features(url: str) -> pd.DataFrame:
    """
    Extracts the exact 21 URL-only features the model was trained on.
    All features computed purely from the URL string — no page fetching.
    """
    url    = str(url).strip()
    parsed = urlparse(url if "://" in url else "http://" + url)
    host   = parsed.hostname or ""
    tld    = _get_tld(host)
    domain = host.split(".")[-2] if len(host.split(".")) >= 2 else host

    # Character counts
    letters       = sum(c.isalpha() for c in url)
    digits        = sum(c.isdigit() for c in url)
    special_chars = sum(not c.isalnum() and c not in "/:.-_~?=#&@%+"
                        for c in url)
    obfuscated    = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    url_len       = max(len(url), 1)

    features = {
        "URLLength":                 len(url),
        "URLSimilarityIndex":        _url_similarity_index(url),
        "CharContinuationRate":      _char_continuation_rate(url),
        "TLDLegitimateProb":         TLD_LEGIT_PROB.get(tld, 0.001),
        "URLCharProb":               _url_char_prob(url),
        "TLDLength":                 len(tld),
        "NoOfSubDomain":             max(len(host.split(".")) - 2, 0),
        "HasObfuscation":            1 if obfuscated > 0 else 0,
        "NoOfObfuscatedChar":        obfuscated,
        "ObfuscationRatio":          round(obfuscated / url_len, 6),
        "LetterRatioInURL":          round(letters / url_len, 3),
        "NoOfDegitsInURL":           digits,
        "DegitRatioInURL":           round(digits / url_len, 3),
        "NoOfEqualsInURL":           url.count("="),
        "NoOfQMarkInURL":            url.count("?"),
        "NoOfAmpersandInURL":        url.count("&"),
        "NoOfOtherSpecialCharsInURL":special_chars,
        "SpacialCharRatioInURL":     round(special_chars / url_len, 3),
        "IsHTTPS":                   1 if url.lower().startswith("https") else 0,
        "IsDomainIP":                _is_ip(host),
        "DomainLength":              len(domain),
    }

    return pd.DataFrame([features], columns=URL_FEATURES)


# ── Simple cache keyed by URL ─────────────────────────────
_ML_CACHE: dict[str, dict] = {}


def get_ml_prediction(url: str) -> dict:
    """
    Performs inference and SHAP explanation on a URL.

    Returns:
        dict with verdict, confidence score, and per-feature SHAP impacts.
    """
    if url in _ML_CACHE:
        return _ML_CACHE[url]

    if LGBM_MODEL is None or SHAP_EXPLAINER is None:
        result = {
            "verdict":          "ERROR",
            "confidence_score": 0.0,
            "message":          "ML Engine or Explainer not loaded"
        }
        _ML_CACHE[url] = result
        return result

    try:
        features_df = extract_url_features(url)

        # ── Prediction ────────────────────────────────────
        # Native LightGBM uses predict() not predict_proba()
        prob = float(LGBM_MODEL.predict(features_df)[0])

        # ── SHAP explanation ──────────────────────────────
        shap_values = SHAP_EXPLAINER.shap_values(features_df)

        # LightGBM native returns single array for binary classification
        # sklearn wrapper returns list [neg_class, pos_class]
        if isinstance(shap_values, list):
            contributions = shap_values[1][0]   # positive class
        elif shap_values.ndim == 2:
            contributions = shap_values[0]       # single row
        else:
            contributions = shap_values

        explanation = {
            name: round(float(val), 4)
            for name, val in zip(URL_FEATURES, contributions)
        }

        # ── Verdict using trained threshold ───────────────
        if prob >= MODEL_THRESHOLD:
            label = "MALICIOUS"
        elif prob >= MODEL_THRESHOLD * 0.6:   # 60% of threshold = suspicious zone
            label = "SUSPICIOUS"
        else:
            label = "CLEAN"

        result = {
            "verdict":          label,
            "confidence_score": round(prob, 4),
            "feature_impacts":  explanation,
            "engine":           "LightGBM + SHAP Explainer"
        }
        _ML_CACHE[url] = result
        return result

    except Exception as error:
        result = {
            "verdict":          "ERROR",
            "confidence_score": 0.0,
            "message":          f"Analysis failed: {str(error)}"
        }
        _ML_CACHE[url] = result
        return result