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

# Install system dependencies (including PostgreSQL client and git for foundry)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq-dev \
    gcc \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (Anvil) for transaction simulation
# Using foundryup installer which downloads pre-built binaries
ENV FOUNDRY_DIR=/usr/local/foundry
RUN mkdir -p $FOUNDRY_DIR && \
    curl -L https://foundry.paradigm.xyz | bash && \
    /root/.foundry/bin/foundryup && \
    cp /root/.foundry/bin/anvil /usr/local/bin/anvil && \
    cp /root/.foundry/bin/cast /usr/local/bin/cast && \
    cp /root/.foundry/bin/forge /usr/local/bin/forge && \
    chmod +x /usr/local/bin/anvil /usr/local/bin/cast /usr/local/bin/forge && \
    rm -rf /root/.foundry

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY frontend/ ./frontend/
COPY monitor.py .
COPY entrypoint.sh /app/entrypoint.sh

# Make entrypoint executable and create non-root user for security
RUN chmod +x /app/entrypoint.sh && \
    useradd --create-home --shell /bin/bash xdr && \
    chown -R xdr:xdr /app

USER xdr

# Expose ports (API: 8080, Worker: 9090)
EXPOSE 8080 9090

# Health check (defaults to worker port 9090)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9090}/health || exit 1

# Default: Run worker
# Override with: docker run -e PROC_TYPE=api ... for API-only mode
ENTRYPOINT ["/app/entrypoint.sh"]

