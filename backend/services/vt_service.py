"""
VirusTotal Service module for fetching global threat intelligence.
This module handles URL encoding and API communication with VirusTotal.
"""

import os
import base64
import requests
from dotenv import load_dotenv

# Load the VirusTotal API key from the .env file in the project root
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

# simple in-memory cache to avoid repeated API calls
_VT_CACHE: dict[str, dict] = {}

def get_virus_total_report(url: str) -> dict:
    """
    Analyzes a URL using the VirusTotal v3 API and returns a structured report.
    Responses are cached for the lifetime of the process to improve
    performance when the same URL is requested multiple times.

    The cache entries are also retroactively updated to include `vt_score`
    (percentage of engines marking the site malicious) in case the cache
    was populated before that field existed.

    Args:
        url (str): The raw URL string to analyze.

    Returns:
        dict: A dictionary containing the threat verdict and detailed engine stats.
    """
    # return cached result if present, updating vt_score if absent
    if url in _VT_CACHE:
        cached = _VT_CACHE[url]
        if "vt_score" not in cached:
            total = cached.get("total_engines", 0)
            if total > 0:
                cached["vt_score"] = round((cached.get("malicious_count", 0) / total) * 100, 2)
            else:
                cached["vt_score"] = 0.0
        return cached

    if not API_KEY:
        result = {
            "verdict": "ERROR",
            "message": "API Key missing. Check your .env file."
        }
        _VT_CACHE[url] = result
        return result

    try:
        # VirusTotal requires the URL to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"

        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }

        response = requests.get(endpoint, headers=headers, timeout=5)

        if response.status_code == 200:
            attributes = response.json()['data']['attributes']
            stats = attributes['last_analysis_stats']

            # Logic to determine a simplified verdict for the UI
            if stats.get('malicious', 0) > 0:
                verdict = "MALICIOUS"
            elif stats.get('suspicious', 0) > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"

            total = sum(stats.values())
            # percentage of engines flagging URL as malicious
            vt_score = round((stats.get('malicious', 0) / total) * 100, 2) if total > 0 else 0.0

            result = {
                "verdict": verdict,
                "malicious_count": stats.get('malicious', 0),
                "suspicious_count": stats.get('suspicious', 0),
                "total_engines": total,
                "vt_score": vt_score,
                "reputation": attributes.get('reputation', 0),
                "engine": "VirusTotal v3 API"
            }
            _VT_CACHE[url] = result
            return result

        if response.status_code == 404:
            result = {"verdict": "NOT_FOUND", "message": "URL not in VT database."}
            _VT_CACHE[url] = result
            return result

        result = {
            "verdict": "ERROR", 
            "message": f"API returned status code {response.status_code}"
        }
        _VT_CACHE[url] = result
        return result

    except requests.exceptions.RequestException as error:
        result = {"verdict": "CONNECTION_FAILED", "message": str(error)}
        _VT_CACHE[url] = result
        return result