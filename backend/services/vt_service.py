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

def get_virus_total_report(url: str) -> dict:
    """
    Analyzes a URL using the VirusTotal v3 API and returns a structured report.
    
    Args:
        url (str): The raw URL string to analyze.
        
    Returns:
        dict: A dictionary containing the threat verdict and detailed engine stats.
    """
    if not API_KEY:
        return {
            "verdict": "ERROR",
            "message": "API Key missing. Check your .env file."
        }

    try:
        # VirusTotal requires the URL to be base64 encoded without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        
        headers = {
            "accept": "application/json",
            "x-apikey": API_KEY
        }
        
        response = requests.get(endpoint, headers=headers, timeout=10)
        
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
                
            return {
                "verdict": verdict,
                "malicious_count": stats.get('malicious', 0),
                "suspicious_count": stats.get('suspicious', 0),
                "total_engines": sum(stats.values()),
                "reputation": attributes.get('reputation', 0),
                "engine": "VirusTotal v3 API"
            }
            
        if response.status_code == 404:
            return {"verdict": "NOT_FOUND", "message": "URL not in VT database."}
            
        return {
            "verdict": "ERROR", 
            "message": f"API returned status code {response.status_code}"
        }

    except requests.exceptions.RequestException as error:
        return {"verdict": "CONNECTION_FAILED", "message": str(error)}