#!/bin/bash
# Quick Secret Setup - Copy-paste ready commands
# Run these commands one by one in your terminal or Cloud Shell

set -e

echo "=============================================================================="
echo "Sentinel3 - Quick Secret Setup"
echo "=============================================================================="
echo ""

# Step 1: Set your project (change if different)
export PROJECT_ID="web3-xdr"
echo "Project: ${PROJECT_ID}"
echo ""

# Step 2: Check if gcloud is available
if ! command -v gcloud &> /dev/null; then
    echo "ERROR: gcloud CLI not found!"
    echo ""
    echo "Please install gcloud CLI:"
    echo "  macOS: brew install google-cloud-sdk"
    echo "  Or download: https://cloud.google.com/sdk/docs/install"
    echo ""
    echo "OR use Google Cloud Shell: https://shell.cloud.google.com/"
    exit 1
fi

# Step 3: Authenticate (if needed)
echo "Checking authentication..."
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 &> /dev/null; then
    echo "⚠️  Not authenticated. Running: gcloud auth login"
    gcloud auth login
fi

# Step 4: Set project
echo "Setting project to ${PROJECT_ID}..."
gcloud config set project ${PROJECT_ID}

# Step 5: Enable APIs
echo ""
echo "Enabling required APIs..."
gcloud services enable secretmanager.googleapis.com redis.googleapis.com --quiet

# Step 6: Check/create Redis instance
echo ""
echo "Checking Redis instance..."
if gcloud redis instances describe sentinel3-redis --region=us-central1 &>/dev/null; then
    echo "✓ Redis instance exists"
    REDIS_HOST=$(gcloud redis instances describe sentinel3-redis --region=us-central1 --format='value(host)')
else
    echo "Creating Redis instance (this takes 5-10 minutes)..."
    gcloud redis instances create sentinel3-redis \
        --size=1 \
        --region=us-central1 \
        --network=default
    REDIS_HOST=$(gcloud redis instances describe sentinel3-redis --region=us-central1 --format='value(host)')
fi

echo "Redis Host: ${REDIS_HOST}"

# Step 7: Create Redis URL secret
echo ""
echo "Creating Redis URL secret..."
REDIS_URL="redis://${REDIS_HOST}:6379/0"
if gcloud secrets describe web3-xdr-redis-url &>/dev/null; then
    echo "Secret exists, updating..."
    echo -n "${REDIS_URL}" | gcloud secrets versions add web3-xdr-redis-url --data-file=-
else
    echo -n "${REDIS_URL}" | gcloud secrets create web3-xdr-redis-url --data-file=-
fi
echo "✓ Redis URL secret created"

# Step 8: Create Guardian private key secret
echo ""
echo "Creating Guardian private key secret..."
echo "Setting to 'disabled' (change later if needed)"
if gcloud secrets describe web3-xdr-guardian-private-key &>/dev/null; then
    echo "Secret exists, updating..."
    echo -n "disabled" | gcloud secrets versions add web3-xdr-guardian-private-key --data-file=-
else
    echo -n "disabled" | gcloud secrets create web3-xdr-guardian-private-key --data-file=-
fi
echo "✓ Guardian key secret created"

# Step 9: Grant permissions
echo ""
echo "Granting permissions to Cloud Run service account..."
COMPUTE_SA="${PROJECT_ID}@appspot.gserviceaccount.com"
echo "Service Account: ${COMPUTE_SA}"

gcloud secrets add-iam-policy-binding web3-xdr-redis-url \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" 2>/dev/null || echo "  (permission already granted)"

gcloud secrets add-iam-policy-binding web3-xdr-guardian-private-key \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" 2>/dev/null || echo "  (permission already granted)"

echo "✓ Permissions granted"

# Step 10: Verify all secrets
echo ""
echo "=============================================================================="
echo "Verifying all required secrets..."
echo "=============================================================================="

REQUIRED_SECRETS=(
    "web3-xdr-redis-url"
    "web3-xdr-guardian-private-key"
    "web3-xdr-jwt-secret"
    "web3-xdr-database-url"
    "web3-xdr-infura-api-key"
    "web3-xdr-openai-api-key"
)

MISSING=0
for secret in "${REQUIRED_SECRETS[@]}"; do
    if gcloud secrets describe ${secret} &>/dev/null; then
        echo "✓ ${secret}"
    else
        echo "✗ ${secret} (MISSING)"
        MISSING=$((MISSING + 1))
    fi
done

echo ""
if [ $MISSING -eq 0 ]; then
    echo "=============================================================================="
    echo "✓ ALL SECRETS CONFIGURED! Ready to deploy."
    echo "=============================================================================="
    echo ""
    echo "Next steps:"
    echo "  1. git add ."
    echo "  2. git commit -m 'Configure secrets for deployment'"
    echo "  3. git push origin main"
    echo ""
else
    echo "=============================================================================="
    echo "⚠️  ${MISSING} secret(s) missing. Please create them:"
    echo "=============================================================================="
    echo ""
    echo "For each missing secret, run:"
    echo "  echo -n 'YOUR_VALUE' | gcloud secrets create SECRET_NAME --data-file=-"
    echo ""
fi

