#!/bin/bash
# ============================================================================
# Deploy Script - Bundled React + Python Worker
# ============================================================================

set -e  # Exit on error

echo "🚀 Deploying Web3 XDR with Bundled UI..."
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${GCP_PROJECT_ID:-web3-xdr}"
REGION="${GCP_REGION:-us-central1}"
SERVICE_NAME="web3-xdr-worker"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}"

# ============================================================================
# Step 1: Pre-flight Checks
# ============================================================================

echo -e "${BLUE}Step 1: Pre-flight checks...${NC}"

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}❌ gcloud CLI not found. Please install: https://cloud.google.com/sdk/docs/install${NC}"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo -e "${RED}❌ Docker is not running. Please start Docker Desktop.${NC}"
    exit 1
fi

# Check if frontend exists
if [ ! -d "frontend/war-room" ]; then
    echo -e "${RED}❌ Frontend directory not found: frontend/war-room${NC}"
    exit 1
fi

# Check if package.json exists
if [ ! -f "frontend/war-room/package.json" ]; then
    echo -e "${RED}❌ package.json not found in frontend/war-room${NC}"
    exit 1
fi

echo -e "${GREEN}✓ All pre-flight checks passed${NC}"
echo ""

# ============================================================================
# Step 2: Build Frontend Locally (Optional - for verification)
# ============================================================================

echo -e "${BLUE}Step 2: Building frontend locally (for verification)...${NC}"

cd frontend/war-room

# Check if node_modules exists
if [ ! -d "node_modules" ]; then
    echo "Installing npm dependencies..."
    npm install
fi

# Build
echo "Building React app..."
npm run build

# Verify build output
if [ ! -f "dist/index.html" ]; then
    echo -e "${RED}❌ Build failed - dist/index.html not found${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Frontend built successfully${NC}"
echo "Build size: $(du -sh dist | cut -f1)"
cd ../..
echo ""

# ============================================================================
# Step 3: Build Docker Image
# ============================================================================

echo -e "${BLUE}Step 3: Building Docker image...${NC}"

# Build with multi-stage Dockerfile
docker build \
    --platform linux/amd64 \
    -t ${SERVICE_NAME}:latest \
    -t ${IMAGE_NAME}:latest \
    -t ${IMAGE_NAME}:$(date +%Y%m%d-%H%M%S) \
    .

echo -e "${GREEN}✓ Docker image built successfully${NC}"
echo ""

# ============================================================================
# Step 4: Test Locally (Optional)
# ============================================================================

echo -e "${YELLOW}Would you like to test locally before deploying? (y/n)${NC}"
read -r TEST_LOCAL

if [ "$TEST_LOCAL" = "y" ]; then
    echo -e "${BLUE}Step 4: Testing locally...${NC}"
    
    # Stop any existing container
    docker stop ${SERVICE_NAME}-test 2>/dev/null || true
    docker rm ${SERVICE_NAME}-test 2>/dev/null || true
    
    # Run container
    echo "Starting container on port 9090..."
    docker run -d \
        --name ${SERVICE_NAME}-test \
        -p 9090:9090 \
        -e RUNTIME_ENABLED=false \
        ${SERVICE_NAME}:latest
    
    # Wait for container to start
    echo "Waiting for container to start..."
    sleep 5
    
    # Test health endpoint
    echo "Testing health endpoint..."
    if curl -f http://localhost:9090/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Health check passed${NC}"
    else
        echo -e "${RED}❌ Health check failed${NC}"
        docker logs ${SERVICE_NAME}-test
        exit 1
    fi
    
    # Test UI endpoint
    echo "Testing UI endpoint..."
    if curl -f http://localhost:9090/ > /dev/null 2>&1; then
        echo -e "${GREEN}✓ UI endpoint accessible${NC}"
    else
        echo -e "${RED}❌ UI endpoint failed${NC}"
        docker logs ${SERVICE_NAME}-test
        exit 1
    fi
    
    echo -e "${GREEN}✓ Local test passed${NC}"
    echo -e "${BLUE}Access UI at: http://localhost:9090${NC}"
    echo ""
    echo -e "${YELLOW}Press Enter to continue with deployment (or Ctrl+C to stop)...${NC}"
    read -r
    
    # Stop test container
    docker stop ${SERVICE_NAME}-test
    docker rm ${SERVICE_NAME}-test
else
    echo "Skipping local test..."
fi
echo ""

# ============================================================================
# Step 5: Push to Google Container Registry
# ============================================================================

echo -e "${BLUE}Step 5: Pushing image to GCR...${NC}"

# Configure Docker for GCR
gcloud auth configure-docker --quiet

# Push image
docker push ${IMAGE_NAME}:latest

echo -e "${GREEN}✓ Image pushed to GCR${NC}"
echo ""

# ============================================================================
# Step 6: Deploy to Cloud Run
# ============================================================================

echo -e "${BLUE}Step 6: Deploying to Cloud Run...${NC}"

# Get Redis URL from Secret Manager (if exists)
REDIS_URL=""
if gcloud secrets describe web3-xdr-redis-url --project=${PROJECT_ID} &> /dev/null; then
    echo "Found Redis URL secret..."
    REDIS_URL=$(gcloud secrets versions access latest --secret=web3-xdr-redis-url --project=${PROJECT_ID})
fi

# Deploy to Cloud Run
gcloud run deploy ${SERVICE_NAME} \
    --image ${IMAGE_NAME}:latest \
    --platform managed \
    --region ${REGION} \
    --project ${PROJECT_ID} \
    --port 9090 \
    --memory 2Gi \
    --cpu 2 \
    --timeout 3600 \
    --max-instances 10 \
    --min-instances 1 \
    --allow-unauthenticated \
    --set-env-vars="RUNTIME_ENABLED=true,MEMPOOL_SOURCE=pseudo" \
    --set-secrets="DATABASE_URL=web3-xdr-database-url:latest" \
    ${REDIS_URL:+--set-env-vars="REDIS_URL=${REDIS_URL}"}

echo -e "${GREEN}✓ Deployed to Cloud Run${NC}"
echo ""

# ============================================================================
# Step 7: Get Service URL
# ============================================================================

echo -e "${BLUE}Step 7: Getting service URL...${NC}"

SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
    --platform managed \
    --region ${REGION} \
    --project ${PROJECT_ID} \
    --format 'value(status.url)')

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  🎉 Deployment Complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "${BLUE}Service URL:${NC} ${SERVICE_URL}"
echo ""
echo -e "${BLUE}Access Points:${NC}"
echo "  • War Room UI:    ${SERVICE_URL}/"
echo "  • Health Check:   ${SERVICE_URL}/health"
echo "  • Metrics:        ${SERVICE_URL}/metrics"
echo ""
echo -e "${BLUE}Verify Deployment:${NC}"
echo "  curl ${SERVICE_URL}/health"
echo ""
echo -e "${BLUE}View Logs:${NC}"
echo "  gcloud logging read \"resource.type=cloud_run_revision AND resource.labels.service_name=${SERVICE_NAME}\" --limit=50 --project=${PROJECT_ID}"
echo ""
echo -e "${BLUE}Monitor Service:${NC}"
echo "  https://console.cloud.google.com/run/detail/${REGION}/${SERVICE_NAME}?project=${PROJECT_ID}"
echo ""
echo -e "${GREEN}========================================${NC}"
