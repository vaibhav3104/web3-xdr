# Quick Deployment Guide

## Deploy Sentinel3 to GCP Cloud Run

### Option 1: Deploy via GitHub Actions (Recommended)

The system will automatically deploy when you push to:
- **`develop` branch** → Staging environment
- **`main` branch** → Production environment

**Steps:**

1. **Ensure GitHub Secrets are set:**
   - `GCP_SA_KEY`: Service account JSON key with Cloud Run permissions
   - Secrets in GCP Secret Manager:
     - `web3-xdr-infura-api-key`
     - `web3-xdr-jwt-secret`
     - `web3-xdr-openai-api-key`
     - `web3-xdr-database-url`
     - `web3-xdr-redis-url`

2. **Push to trigger deployment:**
   ```bash
   git add .
   git commit -m "Deploy Phase 6: Dual service architecture"
   git push origin main  # or develop for staging
   ```

3. **Monitor deployment:**
   - Go to GitHub Actions tab
   - Watch the deployment workflow
   - Check deployment summary for URLs

### Option 2: Manual Deployment via gcloud CLI

**Prerequisites:**
```bash
# Install gcloud CLI (if not installed)
# https://cloud.google.com/sdk/docs/install

# Authenticate
gcloud auth login
gcloud config set project web3-xdr

# Enable required APIs
gcloud services enable run.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com
```

**Build and Deploy:**

```bash
# Set variables
export GCP_PROJECT="web3-xdr"
export GCP_REGION="us-central1"
export IMAGE_TAG="latest"

# Build Docker image
docker build -t ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/web3-xdr-repo/web3-xdr:${IMAGE_TAG} .

# Configure Docker auth
gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev

# Push to Artifact Registry
docker push ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/web3-xdr-repo/web3-xdr:${IMAGE_TAG}

# Deploy API Service
gcloud run deploy web3-xdr-production-api \
  --image ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/web3-xdr-repo/web3-xdr:${IMAGE_TAG} \
  --region ${GCP_REGION} \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --memory 2Gi \
  --cpu 2 \
  --min-instances 1 \
  --max-instances 10 \
  --set-env-vars "ENVIRONMENT=production,GCP_PROJECT=${GCP_PROJECT},PROC_TYPE=api,API_PORT=8080" \
  --set-secrets "INFURA_API_KEY=web3-xdr-infura-api-key:latest,JWT_SECRET_KEY=web3-xdr-jwt-secret:latest,OPENAI_API_KEY=web3-xdr-openai-api-key:latest,DATABASE_URL=web3-xdr-database-url:latest,REDIS_URL=web3-xdr-redis-url:latest"

# Deploy Worker Service
gcloud run deploy web3-xdr-production-worker \
  --image ${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/web3-xdr-repo/web3-xdr:${IMAGE_TAG} \
  --region ${GCP_REGION} \
  --platform managed \
  --no-allow-unauthenticated \
  --port 9090 \
  --memory 4Gi \
  --cpu 2 \
  --min-instances 1 \
  --max-instances 3 \
  --set-env-vars "ENVIRONMENT=production,GCP_PROJECT=${GCP_PROJECT},PROC_TYPE=worker,WORKER_HEALTH_PORT=9090" \
  --set-secrets "INFURA_API_KEY=web3-xdr-infura-api-key:latest,JWT_SECRET_KEY=web3-xdr-jwt-secret:latest,OPENAI_API_KEY=web3-xdr-openai-api-key:latest,DATABASE_URL=web3-xdr-database-url:latest,REDIS_URL=web3-xdr-redis-url:latest"
```

### Verify Deployment

```bash
# Get service URLs
API_URL=$(gcloud run services describe web3-xdr-production-api --region us-central1 --format='value(status.url)')
WORKER_URL=$(gcloud run services describe web3-xdr-production-worker --region us-central1 --format='value(status.url)')

# Test API health
curl ${API_URL}/health

# Test Worker health (requires auth)
curl ${WORKER_URL}/health

# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-api" --limit=50
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" --limit=50
```

### Post-Deployment Checklist

- [ ] API service is accessible
- [ ] Worker service is running (check logs)
- [ ] Health endpoints respond
- [ ] Database connection works
- [ ] Redis connection works
- [ ] Chains are being monitored (check worker logs)
- [ ] Dashboard is accessible

### Troubleshooting

**If deployment fails:**
1. Check Cloud Logging for errors
2. Verify secrets exist in Secret Manager
3. Check service account permissions
4. Verify Artifact Registry repository exists

**If services don't start:**
1. Check environment variables
2. Verify PROC_TYPE is set correctly (api/worker)
3. Check port configuration (8080 for API, 9090 for Worker)
4. Review container logs

---

**Ready to deploy?** Push to `main` branch or run manual deployment commands above!

