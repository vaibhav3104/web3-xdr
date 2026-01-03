#!/bin/bash
# =============================================================================
# GCP CLOUD RUN DEPLOYMENT SCRIPT for Web3 XDR
# =============================================================================
#
# This script deploys Web3 XDR to Google Cloud using:
# - Artifact Registry for Docker images
# - Cloud Run for serverless container hosting
# - Cloud SQL PostgreSQL for database
# - Cloud Load Balancing for traffic
#
# Prerequisites:
# - gcloud CLI configured with appropriate credentials
# - Docker installed and running
# - APIs enabled: run.googleapis.com, artifactregistry.googleapis.com
#
# Usage:
#   ./deploy-gcp.sh [environment]
#   ./deploy-gcp.sh production
#   ./deploy-gcp.sh staging
#
# =============================================================================

set -e

# Configuration
ENVIRONMENT=${1:-production}
GCP_PROJECT=${GCP_PROJECT:-$(gcloud config get-value project)}
GCP_REGION=${GCP_REGION:-us-central1}
APP_NAME="web3-xdr"
SERVICE_NAME="${APP_NAME}-${ENVIRONMENT}"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║               🚀 GCP CLOUD RUN DEPLOYMENT - Web3 XDR                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Environment: ${ENVIRONMENT}"
echo "Project:     ${GCP_PROJECT}"
echo "Region:      ${GCP_REGION}"
echo ""

# =============================================================================
# Step 1: Enable Required APIs
# =============================================================================
echo "🔧 Step 1: Enabling required APIs..."

gcloud services enable \
    run.googleapis.com \
    artifactregistry.googleapis.com \
    secretmanager.googleapis.com \
    sqladmin.googleapis.com \
    --project=${GCP_PROJECT}

echo "✅ APIs enabled"

# =============================================================================
# Step 2: Create Artifact Registry Repository
# =============================================================================
echo ""
echo "📦 Step 2: Setting up Artifact Registry..."

REPO_NAME="${APP_NAME}-repo"
REPO_LOCATION="${GCP_REGION}"

gcloud artifacts repositories describe ${REPO_NAME} \
    --location=${REPO_LOCATION} \
    --project=${GCP_PROJECT} 2>/dev/null || \
gcloud artifacts repositories create ${REPO_NAME} \
    --repository-format=docker \
    --location=${REPO_LOCATION} \
    --description="Web3 XDR Docker images" \
    --project=${GCP_PROJECT}

echo "✅ Artifact Registry ready"

# =============================================================================
# Step 3: Build and Push Docker Image
# =============================================================================
echo ""
echo "🔨 Step 3: Building and pushing Docker image..."

cd "$(dirname "$0")/../.."

IMAGE_URI="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/${REPO_NAME}/${APP_NAME}:${ENVIRONMENT}"

# Configure Docker for Artifact Registry
gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev --quiet

# Build using Cloud Build (faster, no local Docker needed)
echo "Building with Cloud Build..."
gcloud builds submit \
    --tag ${IMAGE_URI} \
    --project=${GCP_PROJECT} \
    --timeout=20m

echo "✅ Image pushed: ${IMAGE_URI}"

# =============================================================================
# Step 4: Create Secrets (if not exist)
# =============================================================================
echo ""
echo "🔐 Step 4: Setting up secrets..."

# Create secrets (you'll need to add values manually or via CI/CD)
for SECRET_NAME in "postgres-password" "openai-api-key" "infura-api-key" "jwt-secret"; do
    gcloud secrets describe "${APP_NAME}-${SECRET_NAME}" --project=${GCP_PROJECT} 2>/dev/null || \
    gcloud secrets create "${APP_NAME}-${SECRET_NAME}" \
        --project=${GCP_PROJECT} \
        --replication-policy="automatic"
    echo "  ✓ Secret: ${APP_NAME}-${SECRET_NAME}"
done

echo "✅ Secrets configured"
echo "⚠️  Remember to add secret values via Console or CLI"

# =============================================================================
# Step 5: Deploy to Cloud Run
# =============================================================================
echo ""
echo "🚀 Step 5: Deploying to Cloud Run..."

gcloud run deploy ${SERVICE_NAME} \
    --image=${IMAGE_URI} \
    --platform=managed \
    --region=${GCP_REGION} \
    --project=${GCP_PROJECT} \
    --allow-unauthenticated \
    --port=8080 \
    --cpu=1 \
    --memory=1Gi \
    --min-instances=1 \
    --max-instances=10 \
    --concurrency=100 \
    --timeout=300 \
    --set-env-vars="ENVIRONMENT=${ENVIRONMENT},GCP_PROJECT=${GCP_PROJECT}" \
    --set-secrets="POSTGRES_PASSWORD=${APP_NAME}-postgres-password:latest" \
    --set-secrets="OPENAI_API_KEY=${APP_NAME}-openai-api-key:latest" \
    --set-secrets="INFURA_API_KEY=${APP_NAME}-infura-api-key:latest" \
    --set-secrets="JWT_SECRET_KEY=${APP_NAME}-jwt-secret:latest" \
    --labels="app=${APP_NAME},environment=${ENVIRONMENT}"

# Get the service URL
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
    --platform=managed \
    --region=${GCP_REGION} \
    --project=${GCP_PROJECT} \
    --format='value(status.url)')

echo "✅ Deployed to Cloud Run"

# =============================================================================
# Step 6: Set up Cloud SQL (optional)
# =============================================================================
echo ""
echo "📊 Step 6: Cloud SQL setup..."

SQL_INSTANCE="${APP_NAME}-db-${ENVIRONMENT}"

# Check if instance exists
if ! gcloud sql instances describe ${SQL_INSTANCE} --project=${GCP_PROJECT} 2>/dev/null; then
    echo "Creating Cloud SQL instance (this takes ~5 minutes)..."
    gcloud sql instances create ${SQL_INSTANCE} \
        --database-version=POSTGRES_15 \
        --tier=db-f1-micro \
        --region=${GCP_REGION} \
        --project=${GCP_PROJECT} \
        --storage-type=SSD \
        --storage-size=10GB \
        --backup-start-time=03:00 \
        --availability-type=zonal
    
    # Create database
    gcloud sql databases create web3_xdr \
        --instance=${SQL_INSTANCE} \
        --project=${GCP_PROJECT}
    
    # Create user
    gcloud sql users create xdr \
        --instance=${SQL_INSTANCE} \
        --project=${GCP_PROJECT} \
        --password="$(openssl rand -base64 24)"
    
    echo "✅ Cloud SQL instance created"
    echo "⚠️  Update the postgres-password secret with the generated password"
else
    echo "✅ Cloud SQL instance already exists"
fi

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ DEPLOYMENT COMPLETE                              ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "🌐 Service URL:  ${SERVICE_URL}"
echo "📦 Image:        ${IMAGE_URI}"
echo "🗄️  Database:     ${SQL_INSTANCE}"
echo ""
echo "Access your application:"
echo "  Dashboard:     ${SERVICE_URL}/frontend/index.html"
echo "  Admin:         ${SERVICE_URL}/frontend/admin.html"
echo "  API Docs:      ${SERVICE_URL}/api/docs"
echo "  AI Analysis:   ${SERVICE_URL}/api/ai/status"
echo ""
echo "Configure secrets:"
echo "  gcloud secrets versions add ${APP_NAME}-postgres-password --data-file=-"
echo "  gcloud secrets versions add ${APP_NAME}-openai-api-key --data-file=-"
echo ""
echo "View logs:"
echo "  gcloud run services logs read ${SERVICE_NAME} --region=${GCP_REGION}"
echo ""
echo "Monitor:"
echo "  https://console.cloud.google.com/run/detail/${GCP_REGION}/${SERVICE_NAME}"
echo ""

