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
# Download pre-built binaries directly from GitHub releases
ENV FOUNDRY_VERSION=stable
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi && \
    if [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    curl -L "https://github.com/foundry-rs/foundry/releases/download/stable/foundry_stable_linux_${ARCH}.tar.gz" -o /tmp/foundry.tar.gz && \
    tar -xzf /tmp/foundry.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/anvil /usr/local/bin/cast /usr/local/bin/forge /usr/local/bin/chisel && \
    rm /tmp/foundry.tar.gz && \
    anvil --version

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

