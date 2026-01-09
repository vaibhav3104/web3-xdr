#!/bin/bash
# ============================================================================
# Local Deployment - Quick Test
# ============================================================================

set -e

echo "🚀 Building and deploying locally..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# Stop any existing container
echo "Stopping existing containers..."
docker stop web3-xdr-local 2>/dev/null || true
docker rm web3-xdr-local 2>/dev/null || true

# Build Docker image
echo -e "${BLUE}Building Docker image...${NC}"
docker build --platform linux/amd64 -t web3-xdr:local .

echo -e "${GREEN}✓ Image built${NC}"
echo ""

# Run container
echo -e "${BLUE}Starting container...${NC}"
docker run -d \
    --name web3-xdr-local \
    -p 9090:9090 \
    -e RUNTIME_ENABLED=false \
    -e LOG_LEVEL=INFO \
    web3-xdr:local

echo -e "${GREEN}✓ Container started${NC}"
echo ""

# Wait for startup
echo "Waiting for service to start..."
sleep 5

# Test endpoints
echo -e "${BLUE}Testing endpoints...${NC}"

# Health check
if curl -f http://localhost:9090/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓ Health check: OK${NC}"
else
    echo "❌ Health check failed"
    docker logs web3-xdr-local
    exit 1
fi

# UI check
if curl -f http://localhost:9090/ > /dev/null 2>&1; then
    echo -e "${GREEN}✓ UI endpoint: OK${NC}"
else
    echo "❌ UI endpoint failed"
    docker logs web3-xdr-local
    exit 1
fi

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  🎉 Local Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo "  • War Room UI:    http://localhost:9090/"
echo "  • Health Check:   http://localhost:9090/health"
echo "  • Metrics:        http://localhost:9090/metrics"
echo ""
echo -e "${BLUE}View Logs:${NC}"
echo "  docker logs -f web3-xdr-local"
echo ""
echo -e "${BLUE}Stop Container:${NC}"
echo "  docker stop web3-xdr-local"
echo ""
echo -e "${GREEN}========================================${NC}"

# Open browser (macOS)
if command -v open &> /dev/null; then
    echo ""
    echo "Opening browser..."
    sleep 2
    open http://localhost:9090
fi
