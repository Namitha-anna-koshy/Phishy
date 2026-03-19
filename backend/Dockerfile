# /backend/Dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install standard backend dependencies (fastapi, uvicorn, httpx, etc.)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the main backend code
COPY . .

EXPOSE 8000

# Start the main backend server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]