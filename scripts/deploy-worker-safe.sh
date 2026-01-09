#!/bin/bash
# Safe deployment script with retry logic for Cloud Run conflicts

set -e

SERVICE_NAME="web3-xdr-production-worker"
REGION="us-central1"
PROJECT="web3-xdr"
IMAGE_TAG="${1:-latest}"

# Get full image path
if [[ "$IMAGE_TAG" == "latest" ]]; then
    IMAGE="us-central1-docker.pkg.dev/${PROJECT}/web3-xdr-repo/web3-xdr:latest"
else
    IMAGE="us-central1-docker.pkg.dev/${PROJECT}/web3-xdr-repo/web3-xdr:${IMAGE_TAG}"
fi

echo "🚀 Deploying ${SERVICE_NAME}..."
echo "   Image: ${IMAGE}"
echo ""

# Wait for any in-progress deployments to complete
echo "⏳ Checking for in-progress deployments..."
while true; do
    LATEST_CREATED=$(gcloud run services describe ${SERVICE_NAME} \
        --region=${REGION} \
        --project=${PROJECT} \
        --format='value(status.latestCreatedRevisionName)' 2>/dev/null || echo "")
    
    LATEST_READY=$(gcloud run services describe ${SERVICE_NAME} \
        --region=${REGION} \
        --project=${PROJECT} \
        --format='value(status.latestReadyRevisionName)' 2>/dev/null || echo "")
    
    if [ "$LATEST_CREATED" == "$LATEST_READY" ] || [ -z "$LATEST_CREATED" ]; then
        echo "✅ No in-progress deployments"
        break
    else
        echo "   Waiting for deployment to complete... (${LATEST_CREATED})"
        sleep 5
    fi
done

# Retry logic for deployment conflicts
max_retries=5
retry_count=0

while [ $retry_count -lt $max_retries ]; do
    echo ""
    echo "📦 Attempt $((retry_count + 1))/$max_retries: Deploying..."
    
    if gcloud run deploy ${SERVICE_NAME} \
        --image="${IMAGE}" \
        --region=${REGION} \
        --project=${PROJECT} \
        --platform=managed \
        --allow-unauthenticated \
        --port=9090 \
        --memory=4Gi \
        --cpu=2 \
        --min-instances=1 \
        --max-instances=3 \
        --timeout=300 \
        --cpu-boost \
        --update-env-vars="LAST_DEPLOY=$(date +%s)" \
        --quiet; then
        echo ""
        echo "✅ Deployment successful!"
        
        # Get the new revision
        NEW_REVISION=$(gcloud run services describe ${SERVICE_NAME} \
            --region=${REGION} \
            --project=${PROJECT} \
            --format='value(status.latestReadyRevisionName)')
        echo "   New revision: ${NEW_REVISION}"
        
        # Get service URL
        SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
            --region=${REGION} \
            --project=${PROJECT} \
            --format='value(status.url)')
        echo "   Service URL: ${SERVICE_URL}"
        
        exit 0
    else
        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            wait_time=$((10 * retry_count))  # Exponential backoff
            echo "⚠️  Deployment conflict, waiting ${wait_time} seconds before retry..."
            sleep ${wait_time}
        else
            echo ""
            echo "❌ Deployment failed after ${max_retries} attempts"
            echo "   This usually means there's a concurrent deployment in progress."
            echo "   Wait a few minutes and try again, or check GitHub Actions."
            exit 1
        fi
    fi
done
