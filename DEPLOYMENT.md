# Sentinel3 Deployment Guide

## GCP Cloud Run Deployment (Dual Service Model)

This guide covers deploying Sentinel3 to GCP Cloud Run with the split architecture (API + Worker).

---

## Architecture Overview

Sentinel3 uses a **dual service model**:
- **API Service**: FastAPI server (Dashboard + API endpoints)
- **Worker Service**: Blockchain ingestion + detection (background process)

Both services use the **same Docker image** but run with different commands.

---

## Prerequisites

- GCP Project with billing enabled
- `gcloud` CLI installed and authenticated
- Docker installed (for local builds)
- GitHub repository (for CI/CD)

---

## Step 1: Build Docker Image

### Local Build

```bash
# Build image
docker build -t gcr.io/YOUR_PROJECT_ID/sentinel3:latest .

# Test locally
docker run -p 8080:8080 -e PROC_TYPE=api gcr.io/YOUR_PROJECT_ID/sentinel3:latest
docker run -p 9090:9090 -e PROC_TYPE=worker gcr.io/YOUR_PROJECT_ID/sentinel3:latest
```

### Push to GCP Artifact Registry

```bash
# Create Artifact Registry repository
gcloud artifacts repositories create sentinel3 \
    --repository-format=docker \
    --location=us-central1

# Configure Docker auth
gcloud auth configure-docker us-central1-docker.pkg.dev

# Tag and push
docker tag gcr.io/YOUR_PROJECT_ID/sentinel3:latest \
    us-central1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel3/sentinel3:latest

docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel3/sentinel3:latest
```

---

## Step 2: Set Up Infrastructure

### Cloud SQL (PostgreSQL)

```bash
# Create Cloud SQL instance
gcloud sql instances create sentinel3-db \
    --database-version=POSTGRES_14 \
    --tier=db-f1-micro \
    --region=us-central1 \
    --root-password=YOUR_ROOT_PASSWORD

# Create database
gcloud sql databases create web3_xdr --instance=sentinel3-db

# Create user
gcloud sql users create xdr \
    --instance=sentinel3-db \
    --password=YOUR_PASSWORD
```

### Redis (Memorystore)

```bash
# Create Memorystore instance
gcloud redis instances create sentinel3-redis \
    --size=1 \
    --region=us-central1 \
    --network=default
```

### Cloud Run Services

#### API Service

```bash
gcloud run deploy sentinel3-api \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel3/sentinel3:latest \
    --platform=managed \
    --region=us-central1 \
    --allow-unauthenticated \
    --port=8080 \
    --memory=2Gi \
    --cpu=2 \
    --min-instances=1 \
    --max-instances=10 \
    --set-env-vars="PROC_TYPE=api" \
    --set-env-vars="API_PORT=8080" \
    --set-env-vars="DATABASE_URL=postgresql://xdr:YOUR_PASSWORD@/web3_xdr?host=/cloudsql/YOUR_PROJECT_ID:us-central1:sentinel3-db" \
    --set-env-vars="REDIS_URL=redis://YOUR_REDIS_IP:6379/0" \
    --set-env-vars="JWT_SECRET_KEY=YOUR_SECRET_KEY" \
    --add-cloudsql-instances=YOUR_PROJECT_ID:us-central1:sentinel3-db \
    --service-account=sentinel3-api@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

#### Worker Service

```bash
gcloud run deploy sentinel3-worker \
    --image=us-central1-docker.pkg.dev/YOUR_PROJECT_ID/sentinel3/sentinel3:latest \
    --platform=managed \
    --region=us-central1 \
    --no-allow-unauthenticated \
    --port=9090 \
    --memory=4Gi \
    --cpu=2 \
    --min-instances=1 \
    --max-instances=3 \
    --set-env-vars="PROC_TYPE=worker" \
    --set-env-vars="WORKER_HEALTH_PORT=9090" \
    --set-env-vars="DATABASE_URL=postgresql://xdr:YOUR_PASSWORD@/web3_xdr?host=/cloudsql/YOUR_PROJECT_ID:us-central1:sentinel3-db" \
    --set-env-vars="REDIS_URL=redis://YOUR_REDIS_IP:6379/0" \
    --set-env-vars="JWT_SECRET_KEY=YOUR_SECRET_KEY" \
    --set-env-vars="GUARDIAN_PRIVATE_KEY=YOUR_PRIVATE_KEY" \
    --add-cloudsql-instances=YOUR_PROJECT_ID:us-central1:sentinel3-db \
    --service-account=sentinel3-worker@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

---

## Step 3: Environment Variables Reference

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `PROC_TYPE` | Process type (`api` or `worker`) | `api` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://user:pass@host/db` |
| `REDIS_URL` | Redis connection string | `redis://host:6379/0` |
| `JWT_SECRET_KEY` | JWT signing secret | `your-secret-key` |

### API Service Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `API_PORT` | API server port | `8080` |
| `CORS_ORIGINS` | Allowed CORS origins | `*` |

### Worker Service Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WORKER_HEALTH_PORT` | Health server port | `9090` |
| `POLL_INTERVAL_SECONDS` | Polling interval | `2.0` |
| `BATCH_SIZE` | Event batch size | `10` |
| `RPC_TIMEOUT` | RPC request timeout | `30.0` |
| `GUARDIAN_PRIVATE_KEY` | Guardian wallet (dev only) | - |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level | `INFO` |
| `ENVIRONMENT` | Environment name | `production` |
| `METRICS_ENABLED` | Enable Prometheus metrics | `true` |

---

## Step 4: CI/CD Setup (GitHub Actions)

### `.github/workflows/deploy-gcp.yml`

```yaml
name: Deploy to GCP Cloud Run

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - id: 'auth'
        uses: 'google-github-actions/auth@v1'
        with:
          credentials_json: '${{ secrets.GCP_SA_KEY }}'
      
      - name: 'Set up Cloud SDK'
        uses: 'google-github-actions/setup-gcloud@v1'
      
      - name: 'Configure Docker'
        run: |
          gcloud auth configure-docker us-central1-docker.pkg.dev
      
      - name: 'Build and Push Image'
        run: |
          docker build -t us-central1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/sentinel3/sentinel3:${{ github.sha }} .
          docker push us-central1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/sentinel3/sentinel3:${{ github.sha }}
      
      - name: 'Deploy API Service'
        run: |
          gcloud run deploy sentinel3-api \
            --image=us-central1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/sentinel3/sentinel3:${{ github.sha }} \
            --region=us-central1 \
            --platform=managed
      
      - name: 'Deploy Worker Service'
        run: |
          gcloud run deploy sentinel3-worker \
            --image=us-central1-docker.pkg.dev/${{ secrets.GCP_PROJECT_ID }}/sentinel3/sentinel3:${{ github.sha }} \
            --region=us-central1 \
            --platform=managed
```

### GitHub Secrets

- `GCP_PROJECT_ID`: Your GCP project ID
- `GCP_SA_KEY`: Service account JSON key (for CI/CD)

---

## Step 5: Service Account Setup

### Create Service Accounts

```bash
# API Service Account
gcloud iam service-accounts create sentinel3-api \
    --display-name="Sentinel3 API Service"

# Worker Service Account
gcloud iam service-accounts create sentinel3-worker \
    --display-name="Sentinel3 Worker Service"
```

### Grant Permissions

```bash
# Cloud SQL Client (for both)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:sentinel3-api@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:sentinel3-worker@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/cloudsql.client"

# Secret Manager (if using KMS)
gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:sentinel3-worker@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"
```

---

## Step 6: Verify Deployment

### Check Service Status

```bash
# API Service
gcloud run services describe sentinel3-api --region=us-central1

# Worker Service
gcloud run services describe sentinel3-worker --region=us-central1
```

### Test Endpoints

```bash
# API Health
curl https://sentinel3-api-XXXXX.run.app/health

# Worker Health
curl https://sentinel3-worker-XXXXX.run.app/health

# Metrics
curl https://sentinel3-worker-XXXXX.run.app/metrics
```

### Run Verification Script

```bash
# SSH into Cloud Run instance (if possible) or run locally with production URLs
export DATABASE_URL="postgresql://..."
export REDIS_URL="redis://..."
python scripts/verify_system.py
```

---

## Step 7: Monitoring & Logging

### Cloud Logging

Logs are automatically sent to Cloud Logging:

```bash
# View API logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=sentinel3-api" --limit=50

# View Worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=sentinel3-worker" --limit=50
```

### Prometheus Metrics

Worker exposes Prometheus metrics at `/metrics`:

```bash
# Scrape endpoint
curl https://sentinel3-worker-XXXXX.run.app/metrics
```

### Cloud Monitoring

Create dashboards in Cloud Monitoring:
- Worker uptime
- Event ingestion rate
- RPC latency
- Incident count

---

## Step 8: Scaling Configuration

### API Service

- **Min Instances**: 1 (always-on for dashboard)
- **Max Instances**: 10 (auto-scale on traffic)
- **Memory**: 2Gi (sufficient for API)
- **CPU**: 2 (for concurrent requests)

### Worker Service

- **Min Instances**: 1 (always-on for ingestion)
- **Max Instances**: 3 (limited by RPC rate limits)
- **Memory**: 4Gi (for event processing)
- **CPU**: 2 (for parallel chain polling)

---

## Troubleshooting

### Worker Not Processing Events

1. Check Redis connectivity:
   ```bash
   gcloud redis instances describe sentinel3-redis --region=us-central1
   ```

2. Check worker logs:
   ```bash
   gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=sentinel3-worker" --limit=100
   ```

3. Verify RPC endpoints:
   ```bash
   # Check chains.yaml configuration
   # Test RPC connectivity
   ```

### API Not Accessible

1. Check service status:
   ```bash
   gcloud run services describe sentinel3-api --region=us-central1
   ```

2. Check IAM permissions:
   ```bash
   gcloud run services get-iam-policy sentinel3-api --region=us-central1
   ```

3. Verify environment variables:
   ```bash
   gcloud run services describe sentinel3-api --region=us-central1 --format="value(spec.template.spec.containers[0].env)"
   ```

### Database Connection Issues

1. Verify Cloud SQL instance:
   ```bash
   gcloud sql instances describe sentinel3-db
   ```

2. Check Cloud SQL proxy:
   - Ensure `--add-cloudsql-instances` is set correctly
   - Verify service account has `cloudsql.client` role

---

## Production Checklist

- [ ] Cloud SQL instance created and accessible
- [ ] Redis (Memorystore) instance created
- [ ] Service accounts created with correct permissions
- [ ] Environment variables set (secrets in Secret Manager)
- [ ] API service deployed and accessible
- [ ] Worker service deployed and running
- [ ] Health checks passing
- [ ] Metrics endpoint accessible
- [ ] Logs visible in Cloud Logging
- [ ] CI/CD pipeline configured
- [ ] Monitoring dashboards created
- [ ] Backup strategy in place (Cloud SQL backups)

---

## Cost Estimation

### Monthly Costs (Approximate)

- **Cloud SQL (db-f1-micro)**: ~$10/month
- **Memorystore (1GB)**: ~$30/month
- **Cloud Run API (1 instance, always-on)**: ~$20/month
- **Cloud Run Worker (1 instance, always-on)**: ~$40/month
- **Network Egress**: ~$10/month
- **Total**: ~$110/month

*Costs vary based on traffic and usage*

---

## Support

For deployment issues:
1. Check Cloud Logging
2. Run verification script
3. Review this guide
4. Open GitHub issue

---

**Last Updated**: Phase 6 - Non-EVM Integration & System Polish
