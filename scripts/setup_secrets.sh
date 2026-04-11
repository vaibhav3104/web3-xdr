#!/bin/bash
# Sentinel3 - Secret Setup Script
# =============================================================================
# This script sets up required secrets in GCP Secret Manager for deployment.
# Run this BEFORE deploying to ensure Redis and other secrets are configured.
# =============================================================================

set -e  # Exit on error

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo "=============================================================================="
echo "Sentinel3 - Secret Setup Script"
echo "=============================================================================="
echo ""

# Get GCP project
GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project 2>/dev/null)}
if [ -z "$GCP_PROJECT" ]; then
    echo -e "${RED}Error: GCP project not set.${NC}"
    echo "Run: gcloud config set project YOUR_PROJECT_ID"
    exit 1
fi

echo -e "${GREEN}Using GCP Project: ${GCP_PROJECT}${NC}"
echo ""

# Get default compute service account
COMPUTE_SA="${GCP_PROJECT}@appspot.gserviceaccount.com"
echo -e "${YELLOW}Using Compute Service Account: ${COMPUTE_SA}${NC}"
echo ""

# =============================================================================
# Step 1: Check if Redis instance exists
# =============================================================================
echo "Step 1: Checking Redis instance..."
REDIS_INSTANCE="sentinel3-redis"
REDIS_REGION="us-central1"

if gcloud redis instances describe ${REDIS_INSTANCE} --region=${REDIS_REGION} --project=${GCP_PROJECT} &>/dev/null; then
    echo -e "${GREEN}✓ Redis instance '${REDIS_INSTANCE}' exists${NC}"
    REDIS_HOST=$(gcloud redis instances describe ${REDIS_INSTANCE} --region=${REDIS_REGION} --project=${GCP_PROJECT} --format='value(host)')
    echo -e "${GREEN}  Redis Host: ${REDIS_HOST}${NC}"
else
    echo -e "${YELLOW}⚠ Redis instance '${REDIS_INSTANCE}' not found${NC}"
    echo ""
    echo "Creating Redis instance (this may take 5-10 minutes)..."
    gcloud redis instances create ${REDIS_INSTANCE} \
        --size=1 \
        --region=${REDIS_REGION} \
        --project=${GCP_PROJECT} \
        --network=default || {
        echo -e "${RED}Failed to create Redis instance. You may need to:${NC}"
        echo "  1. Enable Memorystore API: gcloud services enable redis.googleapis.com"
        echo "  2. Check billing is enabled"
        echo "  3. Or use an existing Redis instance"
        exit 1
    }
    REDIS_HOST=$(gcloud redis instances describe ${REDIS_INSTANCE} --region=${REDIS_REGION} --project=${GCP_PROJECT} --format='value(host)')
    echo -e "${GREEN}✓ Redis instance created: ${REDIS_HOST}${NC}"
fi

# Get Redis auth string (if password is set)
echo ""
echo "Enter Redis password (or press Enter if no password):"
read -s REDIS_PASSWORD

if [ -z "$REDIS_PASSWORD" ]; then
    REDIS_URL="redis://${REDIS_HOST}:6379/0"
else
    REDIS_URL="redis://:${REDIS_PASSWORD}@${REDIS_HOST}:6379/0"
fi

echo ""

# =============================================================================
# Step 2: Create Redis URL Secret
# =============================================================================
echo "Step 2: Creating Redis URL secret..."
SECRET_NAME="web3-xdr-redis-url"

if gcloud secrets describe ${SECRET_NAME} --project=${GCP_PROJECT} &>/dev/null; then
    echo -e "${YELLOW}Secret '${SECRET_NAME}' already exists. Updating...${NC}"
    echo -n "${REDIS_URL}" | gcloud secrets versions add ${SECRET_NAME} --data-file=- --project=${GCP_PROJECT}
    echo -e "${GREEN}✓ Secret updated${NC}"
else
    echo -n "${REDIS_URL}" | gcloud secrets create ${SECRET_NAME} --data-file=- --project=${GCP_PROJECT}
    echo -e "${GREEN}✓ Secret created${NC}"
fi

# Grant access to compute service account
echo "Granting access to compute service account..."
gcloud secrets add-iam-policy-binding ${SECRET_NAME} \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --project=${GCP_PROJECT} &>/dev/null || echo -e "${YELLOW}Note: Permission may already be granted${NC}"

echo ""

# =============================================================================
# Step 3: Create Guardian Private Key Secret (Optional)
# =============================================================================
echo "Step 3: Setting up Guardian private key..."
GUARDIAN_SECRET="web3-xdr-guardian-private-key"

echo "Enter Guardian private key (or 'disabled' to disable Guardian):"
read -s GUARDIAN_KEY

if [ -z "$GUARDIAN_KEY" ]; then
    GUARDIAN_KEY="disabled"
fi

if gcloud secrets describe ${GUARDIAN_SECRET} --project=${GCP_PROJECT} &>/dev/null; then
    echo -e "${YELLOW}Secret '${GUARDIAN_SECRET}' already exists. Updating...${NC}"
    echo -n "${GUARDIAN_KEY}" | gcloud secrets versions add ${GUARDIAN_SECRET} --data-file=- --project=${GCP_PROJECT}
    echo -e "${GREEN}✓ Secret updated${NC}"
else
    echo -n "${GUARDIAN_KEY}" | gcloud secrets create ${GUARDIAN_SECRET} --data-file=- --project=${GCP_PROJECT}
    echo -e "${GREEN}✓ Secret created${NC}"
fi

# Grant access
gcloud secrets add-iam-policy-binding ${GUARDIAN_SECRET} \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" \
    --project=${GCP_PROJECT} &>/dev/null || echo -e "${YELLOW}Note: Permission may already be granted${NC}"

echo ""

# =============================================================================
# Step 4: Alert Delivery Secrets (Slack + Telegram)
# =============================================================================
echo "Step 4: Setting up alert delivery secrets..."

# Slack Webhook
echo ""
echo "Enter Slack Webhook URL (or press Enter to skip):"
read -s SLACK_URL
if [ -n "$SLACK_URL" ]; then
    SLACK_SECRET="web3-xdr-slack-webhook-url"
    if gcloud secrets describe ${SLACK_SECRET} --project=${GCP_PROJECT} &>/dev/null; then
        echo -n "${SLACK_URL}" | gcloud secrets versions add ${SLACK_SECRET} --data-file=- --project=${GCP_PROJECT}
    else
        echo -n "${SLACK_URL}" | gcloud secrets create ${SLACK_SECRET} --data-file=- --project=${GCP_PROJECT}
    fi
    gcloud secrets add-iam-policy-binding ${SLACK_SECRET} \
        --member="serviceAccount:${COMPUTE_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --project=${GCP_PROJECT} &>/dev/null || true
    echo -e "${GREEN}✓ Slack webhook secret configured${NC}"
else
    echo -e "${YELLOW}⚠ Slack webhook skipped${NC}"
fi

# Telegram Bot Token
echo ""
echo "Enter Telegram Bot Token (or press Enter to skip):"
read -s TG_TOKEN
if [ -n "$TG_TOKEN" ]; then
    TG_TOKEN_SECRET="web3-xdr-telegram-bot-token"
    if gcloud secrets describe ${TG_TOKEN_SECRET} --project=${GCP_PROJECT} &>/dev/null; then
        echo -n "${TG_TOKEN}" | gcloud secrets versions add ${TG_TOKEN_SECRET} --data-file=- --project=${GCP_PROJECT}
    else
        echo -n "${TG_TOKEN}" | gcloud secrets create ${TG_TOKEN_SECRET} --data-file=- --project=${GCP_PROJECT}
    fi
    gcloud secrets add-iam-policy-binding ${TG_TOKEN_SECRET} \
        --member="serviceAccount:${COMPUTE_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --project=${GCP_PROJECT} &>/dev/null || true
    echo -e "${GREEN}✓ Telegram bot token secret configured${NC}"
else
    echo -e "${YELLOW}⚠ Telegram bot token skipped${NC}"
fi

# Telegram Channel ID
echo ""
echo "Enter Telegram Channel ID (or press Enter to skip):"
read TG_CHANNEL
if [ -n "$TG_CHANNEL" ]; then
    TG_CHANNEL_SECRET="web3-xdr-telegram-channel-id"
    if gcloud secrets describe ${TG_CHANNEL_SECRET} --project=${GCP_PROJECT} &>/dev/null; then
        echo -n "${TG_CHANNEL}" | gcloud secrets versions add ${TG_CHANNEL_SECRET} --data-file=- --project=${GCP_PROJECT}
    else
        echo -n "${TG_CHANNEL}" | gcloud secrets create ${TG_CHANNEL_SECRET} --data-file=- --project=${GCP_PROJECT}
    fi
    gcloud secrets add-iam-policy-binding ${TG_CHANNEL_SECRET} \
        --member="serviceAccount:${COMPUTE_SA}" \
        --role="roles/secretmanager.secretAccessor" \
        --project=${GCP_PROJECT} &>/dev/null || true
    echo -e "${GREEN}✓ Telegram channel ID secret configured${NC}"
else
    echo -e "${YELLOW}⚠ Telegram channel ID skipped${NC}"
fi

echo ""

# =============================================================================
# Step 5: Verify other required secrets exist
# =============================================================================
echo "Step 5: Verifying other required secrets..."
REQUIRED_SECRETS=(
    "web3-xdr-jwt-secret"
    "web3-xdr-database-url"
    "web3-xdr-infura-api-key"
    "web3-xdr-openai-api-key"
    "web3-xdr-slack-webhook-url"
    "web3-xdr-telegram-bot-token"
    "web3-xdr-telegram-channel-id"
)

MISSING_SECRETS=()
for secret in "${REQUIRED_SECRETS[@]}"; do
    if gcloud secrets describe ${secret} --project=${GCP_PROJECT} &>/dev/null; then
        echo -e "${GREEN}✓ ${secret}${NC}"
    else
        echo -e "${RED}✗ ${secret} (MISSING)${NC}"
        MISSING_SECRETS+=("${secret}")
    fi
done

echo ""

# =============================================================================
# Summary
# =============================================================================
echo "=============================================================================="
echo "Summary"
echo "=============================================================================="
echo ""

if [ ${#MISSING_SECRETS[@]} -eq 0 ]; then
    echo -e "${GREEN}✓ All required secrets are configured!${NC}"
    echo ""
    echo "You can now deploy Sentinel3:"
    echo "  git push origin main  # Deploys to production"
    echo "  git push origin develop  # Deploys to staging"
else
    echo -e "${YELLOW}⚠ Some secrets are missing:${NC}"
    for secret in "${MISSING_SECRETS[@]}"; do
        echo "  - ${secret}"
    done
    echo ""
    echo "Create missing secrets with:"
    echo "  echo -n 'YOUR_VALUE' | gcloud secrets create SECRET_NAME --data-file=-"
fi

echo ""
echo "=============================================================================="

