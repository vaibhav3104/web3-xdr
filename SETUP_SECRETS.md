# Setting Up GCP Secrets for Sentinel3 Deployment

## Quick Setup Guide

Before deploying Sentinel3, you need to set up secrets in GCP Secret Manager. Follow these steps:

---

## Option 1: Automated Setup (Recommended)

Run the setup script:

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
./scripts/setup_secrets.sh
```

The script will:
1. Check/create Redis instance
2. Create Redis URL secret
3. Create Guardian private key secret
4. Verify all required secrets exist
5. Grant permissions to Cloud Run service accounts

---

## Option 2: Manual Setup

### Prerequisites

```bash
# Ensure you're authenticated
gcloud auth login
gcloud config set project web3-xdr  # or your project ID

# Enable Secret Manager API
gcloud services enable secretmanager.googleapis.com
```

### Step 1: Create Redis Instance (if needed)

```bash
# Check if Redis instance exists
gcloud redis instances describe sentinel3-redis --region=us-central1

# If not, create it (takes 5-10 minutes)
gcloud redis instances create sentinel3-redis \
    --size=1 \
    --region=us-central1 \
    --network=default
```

### Step 2: Get Redis Connection Details

```bash
# Get Redis host
REDIS_HOST=$(gcloud redis instances describe sentinel3-redis \
    --region=us-central1 \
    --format='value(host)')

echo "Redis Host: ${REDIS_HOST}"
```

### Step 3: Create Redis URL Secret

```bash
# Format: redis://:password@host:port/0
# If no password: redis://host:port/0

# With password:
echo -n "redis://:YOUR_PASSWORD@${REDIS_HOST}:6379/0" | \
    gcloud secrets create web3-xdr-redis-url --data-file=-

# Without password:
echo -n "redis://${REDIS_HOST}:6379/0" | \
    gcloud secrets create web3-xdr-redis-url --data-file=-
```

### Step 4: Create Guardian Private Key Secret

```bash
# Option A: Set actual private key (if ready for production)
echo -n "YOUR_PRIVATE_KEY_HEX" | \
    gcloud secrets create web3-xdr-guardian-private-key --data-file=-

# Option B: Set to "disabled" (if not ready)
echo -n "disabled" | \
    gcloud secrets create web3-xdr-guardian-private-key --data-file=-
```

### Step 5: Grant Permissions to Cloud Run

```bash
# Get your project's compute service account
PROJECT_ID=$(gcloud config get-value project)
COMPUTE_SA="${PROJECT_ID}@appspot.gserviceaccount.com"

# Grant access to Redis URL secret
gcloud secrets add-iam-policy-binding web3-xdr-redis-url \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor"

# Grant access to Guardian key secret
gcloud secrets add-iam-policy-binding web3-xdr-guardian-private-key \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor"
```

### Step 6: Verify All Secrets Exist

```bash
# List all secrets
gcloud secrets list --filter="name:web3-xdr-*"

# Required secrets:
# ✓ web3-xdr-redis-url (NEW - Phase 6)
# ✓ web3-xdr-guardian-private-key (NEW - Phase 5)
# ✓ web3-xdr-jwt-secret
# ✓ web3-xdr-database-url
# ✓ web3-xdr-infura-api-key
# ✓ web3-xdr-openai-api-key
```

---

## Complete Secret Setup Commands

Here's a complete script you can copy-paste (replace values as needed):

```bash
#!/bin/bash
set -e

PROJECT_ID="web3-xdr"  # Change to your project ID
REGION="us-central1"
COMPUTE_SA="${PROJECT_ID}@appspot.gserviceaccount.com"

# Set project
gcloud config set project ${PROJECT_ID}

# 1. Create Redis instance (if needed)
if ! gcloud redis instances describe sentinel3-redis --region=${REGION} &>/dev/null; then
    echo "Creating Redis instance..."
    gcloud redis instances create sentinel3-redis \
        --size=1 \
        --region=${REGION} \
        --network=default
fi

# 2. Get Redis host
REDIS_HOST=$(gcloud redis instances describe sentinel3-redis \
    --region=${REGION} \
    --format='value(host)')

# 3. Create Redis URL secret
echo -n "redis://${REDIS_HOST}:6379/0" | \
    gcloud secrets create web3-xdr-redis-url --data-file=- 2>/dev/null || \
    echo -n "redis://${REDIS_HOST}:6379/0" | \
    gcloud secrets versions add web3-xdr-redis-url --data-file=-

# 4. Create Guardian key secret (set to "disabled" if not ready)
echo -n "disabled" | \
    gcloud secrets create web3-xdr-guardian-private-key --data-file=- 2>/dev/null || \
    echo -n "disabled" | \
    gcloud secrets versions add web3-xdr-guardian-private-key --data-file=-

# 5. Grant permissions
gcloud secrets add-iam-policy-binding web3-xdr-redis-url \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" 2>/dev/null || true

gcloud secrets add-iam-policy-binding web3-xdr-guardian-private-key \
    --member="serviceAccount:${COMPUTE_SA}" \
    --role="roles/secretmanager.secretAccessor" 2>/dev/null || true

echo "✓ Secrets configured!"
```

---

## Troubleshooting

### Error: "Secret already exists"

If a secret already exists, use `versions add` instead:

```bash
echo -n "new_value" | gcloud secrets versions add SECRET_NAME --data-file=-
```

### Error: "Permission denied"

Ensure you have the `secretmanager.admin` role:

```bash
gcloud projects add-iam-policy-binding ${PROJECT_ID} \
    --member="user:$(gcloud config get-value account)" \
    --role="roles/secretmanager.admin"
```

### Error: "Redis instance not found"

Create the Redis instance first (see Step 1 above).

---

## Verification

After setup, verify secrets are accessible:

```bash
# List all secrets
gcloud secrets list --filter="name:web3-xdr-*"

# Test reading a secret (will show masked value)
gcloud secrets versions access latest --secret="web3-xdr-redis-url"
```

---

## Next Steps

Once secrets are configured:

1. **Verify setup:**
   ```bash
   ./scripts/setup_secrets.sh  # Will verify all secrets
   ```

2. **Deploy:**
   ```bash
   git add .
   git commit -m "Configure secrets for deployment"
   git push origin main  # Deploys to production
   ```

---

**Ready to deploy!** 🚀

