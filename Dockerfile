FROM python:3.11-slim

LABEL maintainer="VBSKS Security Team <info@vbsks.com>"
LABEL description="Vector-Based Secure Key Storage"
LABEL version="1.0.0"

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY *.py .

# Create a volume for persistent data
VOLUME ["/app/vbsks_data"]

# Set environment variables
ENV VBSKS_DB_FOLDER=/app/vbsks_data
ENV VBSKS_API_HOST=0.0.0.0
ENV VBSKS_API_PORT=5000
ENV VBSKS_API_DEBUG=false
# Set a random API key if none is provided
ENV VBSKS_API_KEY=""

# Expose the API port
EXPOSE 5000

# Run the API server
CMD ["python", "vbsks_api.py"] 