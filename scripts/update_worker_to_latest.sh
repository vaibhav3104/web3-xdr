#!/bin/bash
# ============================================================================
# Update Worker to Latest Image
# ============================================================================
# This script updates the web3-xdr-production-worker Cloud Run service
# to use the latest Docker image, which includes the fallback fix for
# the status column schema mismatch.
#
# Usage: ./scripts/update_worker_to_latest.sh
# ============================================================================

set -e

GCP_PROJECT="web3-xdr"
REGION="us-central1"
SERVICE_NAME="web3-xdr-production-worker"
IMAGE_REPO="us-central1-docker.pkg.dev/web3-xdr/web3-xdr-repo/web3-xdr"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Update Worker to Latest Image"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 1: Get the latest image
echo "📦 Step 1: Finding latest Docker image..."
# Get most recent image (sorted by timestamp)
# Prefer commit hash tag, fallback to 'latest' or digest
IMAGE_INFO=$(gcloud container images list-tags ${IMAGE_REPO} \
    --limit=5 \
    --project=${GCP_PROJECT} \
    --sort-by=~timestamp \
    --format="json" 2>/dev/null | python3 -c "
import sys, json
try:
    images = json.load(sys.stdin)
    for img in images:
        tags = img.get('tags') or []
        digest = img.get('digest', '')
        # Find commit-hash-like tag (40 char hex)
        for t in tags:
            if t != 'latest' and len(t) >= 7 and len(t) <= 40:
                print(f'{t}|{digest}', end='')
                sys.exit(0)
        # No commit tag, use digest if available
        if digest:
            print(f'@|{digest}', end='')
            sys.exit(0)
except: 
    pass
print('latest|', end='')
" 2>/dev/null | head -1)

if [ -n "$IMAGE_INFO" ]; then
    IMAGE_TAG=$(echo "$IMAGE_INFO" | cut -d'|' -f1)
    IMAGE_DIGEST=$(echo "$IMAGE_INFO" | cut -d'|' -f2)
    
    if [ "$IMAGE_TAG" = "@" ] && [ -n "$IMAGE_DIGEST" ]; then
        FULL_IMAGE="${IMAGE_REPO}@${IMAGE_DIGEST}"
        echo "   Using image (by digest): ${FULL_IMAGE}"
    elif [ -n "$IMAGE_TAG" ]; then
        FULL_IMAGE="${IMAGE_REPO}:${IMAGE_TAG}"
        echo "   Using image: ${FULL_IMAGE}"
    else
        FULL_IMAGE="${IMAGE_REPO}:latest"
        echo "   Using image: ${FULL_IMAGE}"
    fi
else
    FULL_IMAGE="${IMAGE_REPO}:latest"
    echo "   Using image: ${FULL_IMAGE} (fallback to latest tag)"
fi

# Step 2: Get current revision (check latestCreatedRevisionName which is more reliable)
echo ""
echo "🔍 Step 2: Checking current revision..."
CURRENT_REVISION=$(gcloud run services describe ${SERVICE_NAME} \
    --region=${REGION} \
    --project=${GCP_PROJECT} \
    --format="value(status.latestCreatedRevisionName)" 2>/dev/null || \
    gcloud run services describe ${SERVICE_NAME} \
    --region=${REGION} \
    --project=${GCP_PROJECT} \
    --format="value(status.latestReadyRevisionName)" 2>/dev/null || echo "unknown")
echo "   Current: ${CURRENT_REVISION}"

# Step 3: Update the service
echo ""
echo "🚀 Step 3: Updating worker service to latest image..."
echo "   Image: ${FULL_IMAGE}"

# Update image and force new revision by updating a timestamp env var
# (Cloud Run may reuse revision if it thinks nothing changed)
FORCE_REVISION=$(date +%s)
echo "   Force revision timestamp: ${FORCE_REVISION}"

# Quote FULL_IMAGE to handle any special characters
# Use --update-env-vars to ensure a new revision is created with the new image
if ! gcloud run services update "${SERVICE_NAME}" \
    --region="${REGION}" \
    --project="${GCP_PROJECT}" \
    --image="${FULL_IMAGE}" \
    --update-env-vars="LAST_IMAGE_UPDATE=${FORCE_REVISION}" \
    --quiet 2>&1; then
    echo "   ❌ Update with env var failed. Trying image-only update..."
    gcloud run services update "${SERVICE_NAME}" \
        --region="${REGION}" \
        --project="${GCP_PROJECT}" \
        --image="${FULL_IMAGE}" \
        --quiet
fi

# Step 4: Wait for new revision
echo ""
echo "⏳ Step 4: Waiting for new revision to be ready (60 seconds)..."
sleep 60

NEW_REVISION=$(gcloud run services describe ${SERVICE_NAME} \
    --region=${REGION} \
    --project=${GCP_PROJECT} \
    --format="value(status.latestCreatedRevisionName)" 2>/dev/null || \
    gcloud run services describe ${SERVICE_NAME} \
    --region=${REGION} \
    --project=${GCP_PROJECT} \
    --format="value(status.latestReadyRevisionName)" 2>/dev/null || echo "unknown")

echo "   New revision: ${NEW_REVISION}"

# Step 5: Verify deployment
echo ""
echo "🔍 Step 5: Verifying deployment..."
if [ "$CURRENT_REVISION" != "$NEW_REVISION" ]; then
    echo "   ✅ New revision deployed: ${NEW_REVISION}"
else
    echo "   ⚠️  Revision unchanged (may already be on latest)"
fi

# Step 6: Check events API
echo ""
echo "📊 Step 6: Checking Events API..."
sleep 15
EVENTS_RESPONSE=$(curl -s "https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app/api/events?limit=5" 2>/dev/null || echo '{"total":0,"events":[]}')
TOTAL_EVENTS=$(echo "$EVENTS_RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('total', 0))" 2>/dev/null || echo "0")

if [ "$TOTAL_EVENTS" -gt 0 ]; then
    echo "   ✅ Events found: ${TOTAL_EVENTS}"
    echo ""
    echo "   Sample events:"
    echo "$EVENTS_RESPONSE" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for i, e in enumerate(d.get('events', [])[:3]):
    print(f\"      • {e.get('chain_id', 'unknown')} | Block {e.get('block_number', 'N/A')} | {e.get('event_type', 'unknown')[:20]}\")
" 2>/dev/null || true
else
    echo "   ⏳ No events yet (may take 1-2 minutes for events to save)"
    echo "   Check Log Explorer: https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app/frontend/logs.html"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Update Complete"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📋 Summary:"
echo "   • Worker image updated to: ${FULL_IMAGE}"
echo "   • New revision: ${NEW_REVISION}"
echo "   • Events in DB: ${TOTAL_EVENTS}"
echo ""
echo "🔗 Log Explorer: https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app/frontend/logs.html"
echo ""
echo "🔍 Check logs for fallback activity:"
echo "   gcloud logging read \"resource.labels.service_name=web3-xdr-production-worker\" \\"
echo "     --limit=30 --project=web3-xdr --format='table(timestamp,textPayload)' \\"
echo "     | grep -i 'fallback\\|events_batch_saved'"
echo ""
