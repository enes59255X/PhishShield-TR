# Use official Python slim image
FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Copy only requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port (default 8000)
EXPOSE 8000

# Load env vars from .env if present and run uvicorn
CMD ["sh", "-c", "uvicorn app:app --host ${HOST:-0.0.0.0} --port ${PORT:-8000} --reload ${RELOAD:-true}"]