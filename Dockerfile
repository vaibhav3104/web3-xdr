# ============================================================================
# Web3 XDR - Production Dockerfile (Multi-Stage Build)
# ============================================================================

# ============================================================================
# Stage 1: Build React Frontend
# ============================================================================
FROM node:18-alpine AS frontend-builder

WORKDIR /build

# Copy frontend package files
COPY frontend/war-room/package.json frontend/war-room/package-lock.json* ./

# Install dependencies
RUN npm install

# Copy frontend source code
COPY frontend/war-room/ ./

# Build the React app
RUN npm run build

# ============================================================================
# Stage 2: Python Backend + Bundled Frontend
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
COPY monitor.py .
# Copy frontend directory (for logs.html and other static HTML files)
COPY frontend/ ./frontend/

# Copy built frontend from Stage 1
COPY --from=frontend-builder /build/dist /app/static

# Create non-root user for security
RUN useradd --create-home --shell /bin/bash xdr && \
    chown -R xdr:xdr /app

USER xdr

# Expose ports (API: 8080, Worker: 9090)
EXPOSE 8080 9090

# Health check (defaults to worker port 9090)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9090}/health || exit 1

# Default: Run worker with bundled UI
# Override with: docker run -e PROC_TYPE=api ... for API-only mode
ENTRYPOINT ["/bin/sh", "-c"]
CMD ["if [ \"$PROC_TYPE\" = \"api\" ]; then python -m src.api.server; else python -m src.worker.main; fi"]

