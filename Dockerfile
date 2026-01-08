# ============================================================================
# Web3 XDR - Production Dockerfile
# ============================================================================

FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Set working directory
WORKDIR /app

# Install system dependencies (including PostgreSQL client)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY frontend/ ./frontend/
COPY monitor.py .

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash xdr && \
    chown -R xdr:xdr /app

USER xdr

# Expose ports (API: 8080, Worker: 9090)
EXPOSE 8080 9090

# Health check (defaults to API port)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${HEALTH_PORT:-8080}/health || exit 1

# Default: Run API server
# Override with: docker run -e PROC_TYPE=worker ...
# Or use: CMD ["python", "-m", "src.worker.main"] for worker mode
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["if [ \"$PROC_TYPE\" = \"worker\" ]; then python -m src.worker.main; else python -m src.api.server; fi"]

