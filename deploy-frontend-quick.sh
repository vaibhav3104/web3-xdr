#!/bin/bash
# Quick deploy frontend as static files

PROJECT="web3-xdr"
REGION="us-central1"
SERVICE="web3-xdr-production"

echo "🚀 Deploying frontend static files to $SERVICE..."

# Use gcloud run deploy with --source and reduced resources
gcloud run deploy $SERVICE \
  --source . \
  --region $REGION \
  --project $PROJECT \
  --platform managed \
  --allow-unauthenticated \
  --cpu 1 \
  --memory 512Mi \
  --min-instances 0 \
  --max-instances 2 \
  --timeout 60 \
  --port 8080 \
  --set-env-vars "PROC_TYPE=api" \
  --quiet

echo ""
echo "✅ Deployment initiated!"
