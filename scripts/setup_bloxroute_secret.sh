#!/bin/bash
# Setup bloXroute Secret in GCP Secret Manager
# =============================================
# 
# This script creates the bloXroute authorization header secret
# and grants the Cloud Run service account access to it.
#
# Usage:
#   ./scripts/setup_bloxroute_secret.sh
#
# Or provide the header directly:
#   BLOXROUTE_AUTH_HEADER="your_header" ./scripts/setup_bloxroute_secret.sh

set -e

GCP_PROJECT="${GCP_PROJECT:-web3-xdr}"
GCP_REGION="${GCP_REGION:-us-central1}"
SECRET_NAME="web3-xdr-bloxroute-auth-header"

echo "=========================================="
echo "bloXroute Secret Setup"
echo "=========================================="
echo "Project: $GCP_PROJECT"
echo "Secret: $SECRET_NAME"
echo ""

# Check if secret already exists
if gcloud secrets describe "$SECRET_NAME" --project="$GCP_PROJECT" &>/dev/null; then
    echo "⚠️  Secret already exists. Updating..."
    UPDATE_MODE="update"
else
    echo "Creating new secret..."
    UPDATE_MODE="create"
fi

# Get authorization header
if [ -z "$BLOXROUTE_AUTH_HEADER" ]; then
    echo "Enter your bloXroute Authorization Header:"
    read -s BLOXROUTE_AUTH_HEADER
    echo ""
fi

if [ -z "$BLOXROUTE_AUTH_HEADER" ]; then
    echo "❌ ERROR: BLOXROUTE_AUTH_HEADER is empty"
    exit 1
fi

# Create or update secret
if [ "$UPDATE_MODE" == "create" ]; then
    echo -n "$BLOXROUTE_AUTH_HEADER" | \
        gcloud secrets create "$SECRET_NAME" \
            --project="$GCP_PROJECT" \
            --data-file=-
    echo "✅ Secret created"
else
    echo -n "$BLOXROUTE_AUTH_HEADER" | \
        gcloud secrets versions add "$SECRET_NAME" \
            --project="$GCP_PROJECT" \
            --data-file=-
    echo "✅ Secret updated"
fi

# Get Cloud Run service account
SERVICE_ACCOUNT=$(gcloud projects describe "$GCP_PROJECT" --format="value(projectNumber)")-compute@developer.gserviceaccount.com

echo ""
echo "Granting access to Cloud Run service account..."
gcloud secrets add-iam-policy-binding "$SECRET_NAME" \
    --project="$GCP_PROJECT" \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor" \
    --quiet

echo "✅ Access granted to $SERVICE_ACCOUNT"
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Next steps:"
echo "1. Update Cloud Run service to use bloXroute:"
echo "   gcloud run services update web3-xdr-production-worker \\"
echo "     --region=$GCP_REGION \\"
echo "     --update-env-vars MEMPOOL_SOURCE=bloxroute"
echo ""
echo "2. Or let CI/CD handle it (already configured in deploy.yml)"
echo ""

