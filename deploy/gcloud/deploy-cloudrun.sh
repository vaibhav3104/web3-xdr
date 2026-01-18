#!/bin/bash
# Non-interactive Cloud Run deployment script
# Usage: ./deploy-cloudrun.sh <PROJECT_ID> <POSTGRES_PASSWORD> <REDIS_PASSWORD>

set -e

PROJECT_ID=${1:-"web3-xdr"}
POSTGRES_PASSWORD=${2:-"sentinel3-db-pass"}
REDIS_PASSWORD=${3:-"sentinel3-redis-pass"}
REGION="us-central1"

echo -e "\033[0;32m============================================\033[0m"
echo -e "\033[0;32m  Sentinel3 Cloud Run GPU Deployment\033[0m"
echo -e "\033[0;32m============================================\033[0m"

# Set project
echo -e "\n\033[1;33m[1/7] Setting project to: $PROJECT_ID\033[0m"
gcloud config set project $PROJECT_ID

# Enable APIs
echo -e "\n\033[1;33m[2/7] Enabling required APIs...\033[0m"
gcloud services enable \
    artifactregistry.googleapis.com \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    secretmanager.googleapis.com \
    sqladmin.googleapis.com \
    redis.googleapis.com

# Create Artifact Registry repository
echo -e "\n\033[1;33m[3/7] Creating Artifact Registry...\033[0m"
gcloud artifacts repositories create sentinel3 \
    --repository-format=docker \
    --location=$REGION \
    --description="Sentinel3 Docker images" \
    2>/dev/null || echo "Repository already exists"

# Store secrets
echo -e "\n\033[1;33m[4/7] Setting up secrets...\033[0m"
echo -n "$POSTGRES_PASSWORD" | gcloud secrets create sentinel3-db-password --data-file=- 2>/dev/null || \
    echo -n "$POSTGRES_PASSWORD" | gcloud secrets versions add sentinel3-db-password --data-file=-

echo -n "$REDIS_PASSWORD" | gcloud secrets create sentinel3-redis-password --data-file=- 2>/dev/null || \
    echo -n "$REDIS_PASSWORD" | gcloud secrets versions add sentinel3-redis-password --data-file=-

# Build and push Docker image
echo -e "\n\033[1;33m[5/7] Building Docker image with GPU support...\033[0m"
cd "$(dirname "$0")/../.."  # Go to project root

# Use Cloud Build with config file
cat > /tmp/cloudbuild-gpu.yaml << EOF
steps:
  - name: 'gcr.io/cloud-builders/docker'
    args:
      - 'build'
      - '-t'
      - '$REGION-docker.pkg.dev/$PROJECT_ID/sentinel3/sentinel3-gpu:latest'
      - '-f'
      - 'deploy/gcloud/Dockerfile.gpu'
      - '.'
images:
  - '$REGION-docker.pkg.dev/$PROJECT_ID/sentinel3/sentinel3-gpu:latest'
timeout: '1800s'
EOF

gcloud builds submit --config=/tmp/cloudbuild-gpu.yaml .

# Deploy to Cloud Run with GPU
echo -e "\n\033[1;33m[6/7] Deploying to Cloud Run with NVIDIA L4 GPU...\033[0m"
gcloud run deploy sentinel3 \
    --image=$REGION-docker.pkg.dev/$PROJECT_ID/sentinel3/sentinel3-gpu:latest \
    --region=$REGION \
    --platform=managed \
    --cpu=4 \
    --memory=16Gi \
    --gpu=1 \
    --gpu-type=nvidia-l4 \
    --min-instances=0 \
    --max-instances=3 \
    --port=8000 \
    --allow-unauthenticated \
    --set-env-vars="ML_DEVICE=cuda,ML_MODEL_TYPE=transformer,ENVIRONMENT=production" \
    --set-secrets="DATABASE_URL=sentinel3-db-password:latest"

# Get the URL
echo -e "\n\033[1;33m[7/7] Getting service URL...\033[0m"
SERVICE_URL=$(gcloud run services describe sentinel3 --region=$REGION --format='value(status.url)')

echo -e "\n\033[0;32m============================================\033[0m"
echo -e "\033[0;32m  ✅ Deployment Complete!\033[0m"
echo -e "\033[0;32m============================================\033[0m"
echo -e "\n\033[1;36mService URL: $SERVICE_URL\033[0m"
echo -e "\n\033[1;33mNext steps:\033[0m"
echo "1. Set up Cloud SQL PostgreSQL: gcloud sql instances create sentinel3-db --tier=db-f1-micro --region=$REGION"
echo "2. Update DATABASE_URL secret with actual connection string"
echo "3. Visit $SERVICE_URL to access the dashboard"
echo ""
echo -e "\033[1;33mEstimated cost: ~\$0.70/hour when running\033[0m"
