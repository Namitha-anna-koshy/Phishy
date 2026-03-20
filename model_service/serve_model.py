from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

# Import the logic from your existing ml_service file
# (Make sure to move your old ml_service.py into this model_service folder!)
from ml_service import get_ml_prediction

app = FastAPI(title="Phishy ML Microservice")

class PredictionRequest(BaseModel):
    url: str

@app.post("/predict")
async def predict(request: PredictionRequest):
    """
    Receives the URL from the main backend, runs your existing 
    feature extraction and LightGBM logic, and returns the result.
    """
    try:
        # Call your exact existing function
        # Because the model.pkl is now in the same folder (/app), 
        # ensure ml_service.py is looking for it in the current directory.
        results = get_ml_prediction(request.url)
        return results
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Model Inference Failed: {str(e)}"
        )