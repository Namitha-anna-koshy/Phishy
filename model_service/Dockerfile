# /model_service/Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Install the system dependency required specifically for LightGBM
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install ML dependencies (lightgbm, fastapi, uvicorn, pandas, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the model service code and the model.pkl file
COPY . .

EXPOSE 8000

# Start the prediction API
CMD ["uvicorn", "serve_model:app", "--host", "0.0.0.0", "--port", "8000"]