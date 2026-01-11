#!/bin/bash
set -ex

# Force rebuild and deploy script
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Get short SHA
SHORT_SHA=$(git rev-parse --short HEAD)
IMAGE_TAG="rebuild-${SHORT_SHA}-$(date +%s)"

echo "=== Building fresh image: $IMAGE_TAG ==="

# Build with Cloud Build (no cache)
gcloud builds submit \
  --tag us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:$IMAGE_TAG \
  --machine-type=n1-highcpu-8 \
  --timeout=20m

echo "=== Deploying API service ==="
gcloud run deploy web3-xdr-production-api \
  --image us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:$IMAGE_TAG \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --memory 2Gi \
  --cpu 2 \
  --min-instances 1 \
  --max-instances 10 \
  --set-env-vars="PROC_TYPE=api,ENVIRONMENT=production,GCP_PROJECT=web3-xdr" \
  --set-secrets="INFURA_API_KEY=web3-xdr-infura-api-key:latest,JWT_SECRET_KEY=web3-xdr-jwt-secret:latest,OPENAI_API_KEY=web3-xdr-openai-api-key:latest,DATABASE_URL=web3-xdr-database-url:latest,REDIS_URL=web3-xdr-redis-url:latest"

echo "=== Deploying Worker service ==="
gcloud run deploy web3-xdr-production-worker \
  --image us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr:$IMAGE_TAG \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --port 9090 \
  --memory 4Gi \
  --cpu 2 \
  --min-instances 1 \
  --max-instances 5 \
  --timeout 300 \
  --set-env-vars="PROC_TYPE=worker,ENVIRONMENT=production,GCP_PROJECT=web3-xdr,RUNTIME_ENABLED=true,AUTO_START_SCANNER=true" \
  --set-secrets="INFURA_API_KEY=web3-xdr-infura-api-key:latest,JWT_SECRET_KEY=web3-xdr-jwt-secret:latest,OPENAI_API_KEY=web3-xdr-openai-api-key:latest,DATABASE_URL=web3-xdr-database-url:latest,REDIS_URL=web3-xdr-redis-url:latest"

echo "=== Deployment complete! ==="
echo "API: https://web3-xdr-production-api-1003459948096.us-central1.run.app"
echo "Log Explorer: https://web3-xdr-production-api-1003459948096.us-central1.run.app/frontend/logs.html"
