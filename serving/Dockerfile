# Vertex AI Serving Container for Sentinel3 Threat Detector
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements-serving.txt .
RUN pip install --no-cache-dir -r requirements-serving.txt

# Copy model serving code
COPY serve.py .
COPY model/ ./model/

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the server
ENV PORT=8080
EXPOSE 8080

CMD ["python", "serve.py"]
