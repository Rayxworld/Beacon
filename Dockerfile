FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (for better layer caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create data and output directories
RUN mkdir -p /app/data /app/output /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_DIR=/app/logs

# Default command: run Beacon
ENTRYPOINT ["python", "africa_exposed.py"]
CMD ["--help"]
