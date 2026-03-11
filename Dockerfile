# Use a lightweight Python image
FROM python:3.12-slim

# Set the working directory inside the container
WORKDIR /appcd backend

# Copy the requirements first (to cache layers)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
# This includes your .pkl files inside the models/ or services/ folder
COPY . .

# Expose the port FastAPI runs on
EXPOSE 8000

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]