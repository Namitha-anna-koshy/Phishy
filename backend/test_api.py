import requests

def show_demo():
    print("="*40)
    print("PHISHY BACKEND: PROFESSOR DEMO")
    print("="*40)
    
    test_url = "http://phishing-site.example.com"
    print(f"Testing URL: {test_url}\n")
    
    try:
        response = requests.post("http://127.0.0.1:8000/analyze", json={"url": test_url})
        print("API RESPONSE:")
        print(response.json())
    except:
        print("ERROR: Is the FastAPI server running? (uvicorn main:app --reload)")

if __name__ == "__main__":
    show_demo()