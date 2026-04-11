# ============================================================================
# Web3 XDR - Production Dockerfile (Multi-stage)
# ============================================================================

# ── Stage 1: Builder ───────────────────────────────────────────────
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps into a virtual env for clean copy
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .

# PyTorch CPU-only (smaller) then everything else
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# ── Stage 2: Runtime ──────────────────────────────────────────────
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Runtime-only system deps (no gcc, no git)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry (Anvil) for transaction simulation
RUN ARCH=$(uname -m) && \
    if [ "$ARCH" = "x86_64" ]; then ARCH="amd64"; fi && \
    if [ "$ARCH" = "aarch64" ]; then ARCH="arm64"; fi && \
    curl -L "https://github.com/foundry-rs/foundry/releases/download/stable/foundry_stable_linux_${ARCH}.tar.gz" -o /tmp/foundry.tar.gz && \
    tar -xzf /tmp/foundry.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/anvil /usr/local/bin/cast /usr/local/bin/forge /usr/local/bin/chisel && \
    rm /tmp/foundry.tar.gz && \
    anvil --version

# Copy pre-built Python packages from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY src/ ./src/
COPY config/ ./config/
COPY frontend/ ./frontend/
COPY alembic/ ./alembic/
COPY alembic.ini .
COPY monitor.py .
COPY entrypoint.sh /app/entrypoint.sh

# Non-root user
RUN chmod +x /app/entrypoint.sh && \
    useradd --create-home --shell /bin/bash xdr && \
    chown -R xdr:xdr /app

USER xdr

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT:-9090}/health || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
