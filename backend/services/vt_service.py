import os
import base64
import requests
from dotenv import load_dotenv

# Load the VirusTotal API key from the .env file in the project root
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

def get_virus_total_report(url: str):
    """
    Analyzes a URL using the VirusTotal v3 API.
    """
    # VirusTotal requires the URL to be base64 encoded without padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY
    }
    
    try:
        response = requests.get(endpoint, headers=headers)
        if response.status_code == 200:
            data = response.json()['data']['attributes']
            stats = data['last_analysis_stats']
            
            # Logic to determine a simplified verdict for the UI
            if stats['malicious'] > 0:
                verdict = "MALICIOUS"
            elif stats['suspicious'] > 0:
                verdict = "SUSPICIOUS"
            else:
                verdict = "CLEAN"
                
            return {
                "verdict": verdict,
                "malicious_count": stats['malicious'],
                "suspicious_count": stats['suspicious'],
                "total_engines": sum(stats.values()),
                "reputation": data.get('reputation', 0)
            }
        elif response.status_code == 404:
            return {"verdict": "NOT_FOUND", "message": "URL not in VT database."}
        else:
            return {"verdict": "ERROR", "message": f"API returned {response.status_code}"}
    except Exception as e:
        return {"verdict": "CONNECTION_FAILED", "message": str(e)}