#!/bin/bash
# ============================================================================
# Sentinel3 - Google Cloud Setup Script
# ============================================================================
# This script sets up the complete infrastructure on Google Cloud Platform
# with GPU support for the ML transformer model.
#
# Prerequisites:
#   - gcloud CLI installed and authenticated
#   - A Google Cloud project with billing enabled
#   - Sufficient quota for GPUs in your region
#
# Usage:
#   chmod +x setup-gcloud.sh
#   ./setup-gcloud.sh
# ============================================================================

set -e

# Configuration - EDIT THESE
PROJECT_ID="${PROJECT_ID:-your-project-id}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
CLUSTER_NAME="sentinel3-cluster"
DB_INSTANCE_NAME="sentinel3-db"
REDIS_INSTANCE_NAME="sentinel3-redis"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Sentinel3 Google Cloud Setup${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    echo -e "${RED}Error: gcloud CLI is not installed${NC}"
    echo "Install from: https://cloud.google.com/sdk/docs/install"
    exit 1
fi

# Set project
echo -e "${YELLOW}Setting project to: ${PROJECT_ID}${NC}"
gcloud config set project $PROJECT_ID

# Enable required APIs
echo -e "${YELLOW}Enabling required APIs...${NC}"
gcloud services enable \
    container.googleapis.com \
    cloudbuild.googleapis.com \
    run.googleapis.com \
    sqladmin.googleapis.com \
    redis.googleapis.com \
    secretmanager.googleapis.com \
    artifactregistry.googleapis.com

# ============================================================================
# Option 1: Cloud Run with GPU (Simpler)
# ============================================================================

setup_cloud_run() {
    echo -e "${GREEN}Setting up Cloud Run with GPU...${NC}"
    
    # Create Artifact Registry repository
    echo "Creating Artifact Registry repository..."
    gcloud artifacts repositories create sentinel3 \
        --repository-format=docker \
        --location=$REGION \
        --description="Sentinel3 Docker images" \
        || echo "Repository already exists"
    
    # Build and push image
    echo "Building Docker image with GPU support..."
    gcloud builds submit \
        --config=deploy/gcloud/cloudbuild.yaml \
        --substitutions=_REGION=$REGION
    
    echo -e "${GREEN}Cloud Run deployment complete!${NC}"
}

# ============================================================================
# Option 2: GKE with GPU (More Control)
# ============================================================================

setup_gke() {
    echo -e "${GREEN}Setting up GKE cluster with GPU nodes...${NC}"
    
    # Create GKE cluster with GPU node pool
    echo "Creating GKE cluster..."
    gcloud container clusters create $CLUSTER_NAME \
        --zone=$ZONE \
        --num-nodes=2 \
        --machine-type=e2-standard-4 \
        --enable-autoscaling \
        --min-nodes=1 \
        --max-nodes=5 \
        --enable-ip-alias \
        --release-channel=regular
    
    # Add GPU node pool
    echo "Adding GPU node pool..."
    gcloud container node-pools create gpu-pool \
        --cluster=$CLUSTER_NAME \
        --zone=$ZONE \
        --machine-type=n1-standard-4 \
        --accelerator=type=nvidia-tesla-t4,count=1 \
        --num-nodes=1 \
        --enable-autoscaling \
        --min-nodes=0 \
        --max-nodes=3 \
        --node-taints=nvidia.com/gpu=present:NoSchedule
    
    # Install NVIDIA GPU drivers
    echo "Installing NVIDIA GPU drivers..."
    kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/container-engine-accelerators/master/nvidia-driver-installer/cos/daemonset-preloaded.yaml
    
    # Get cluster credentials
    gcloud container clusters get-credentials $CLUSTER_NAME --zone=$ZONE
    
    # Create namespace
    kubectl create namespace sentinel3 || echo "Namespace already exists"
    
    # Create secrets
    echo "Creating Kubernetes secrets..."
    echo -e "${YELLOW}Enter PostgreSQL password:${NC}"
    read -s POSTGRES_PASSWORD
    echo -e "${YELLOW}Enter Infura API key:${NC}"
    read -s INFURA_API_KEY
    
    kubectl create secret generic sentinel3-secrets \
        --from-literal=POSTGRES_PASSWORD=$POSTGRES_PASSWORD \
        --from-literal=INFURA_API_KEY=$INFURA_API_KEY \
        -n sentinel3 \
        || echo "Secrets already exist"
    
    # Deploy application
    echo "Deploying Sentinel3..."
    kubectl apply -f deploy/gcloud/gke-deployment.yaml
    
    # Wait for deployment
    echo "Waiting for deployment to be ready..."
    kubectl rollout status deployment/sentinel3-api -n sentinel3
    
    # Get external IP
    echo -e "${GREEN}Deployment complete!${NC}"
    echo "Getting external IP..."
    kubectl get service sentinel3-api -n sentinel3
}

# ============================================================================
# Setup Cloud SQL (PostgreSQL)
# ============================================================================

setup_database() {
    echo -e "${GREEN}Setting up Cloud SQL (PostgreSQL)...${NC}"
    
    gcloud sql instances create $DB_INSTANCE_NAME \
        --database-version=POSTGRES_14 \
        --tier=db-custom-2-8192 \
        --region=$REGION \
        --storage-size=50GB \
        --storage-type=SSD \
        --storage-auto-increase \
        --backup-start-time=03:00 \
        --availability-type=regional \
        --enable-point-in-time-recovery
    
    # Create database
    gcloud sql databases create web3_xdr --instance=$DB_INSTANCE_NAME
    
    # Create user
    echo -e "${YELLOW}Enter password for database user 'sentinel3':${NC}"
    read -s DB_PASSWORD
    gcloud sql users create sentinel3 \
        --instance=$DB_INSTANCE_NAME \
        --password=$DB_PASSWORD
    
    echo -e "${GREEN}Database setup complete!${NC}"
}

# ============================================================================
# Setup Redis (Memorystore)
# ============================================================================

setup_redis() {
    echo -e "${GREEN}Setting up Memorystore (Redis)...${NC}"
    
    gcloud redis instances create $REDIS_INSTANCE_NAME \
        --size=2 \
        --region=$REGION \
        --redis-version=redis_6_x \
        --tier=standard
    
    # Get Redis IP
    REDIS_IP=$(gcloud redis instances describe $REDIS_INSTANCE_NAME --region=$REGION --format='value(host)')
    echo -e "${GREEN}Redis IP: $REDIS_IP${NC}"
}

# ============================================================================
# Setup Secret Manager
# ============================================================================

setup_secrets() {
    echo -e "${GREEN}Setting up Secret Manager...${NC}"
    
    echo -e "${YELLOW}Enter PostgreSQL password:${NC}"
    read -s POSTGRES_PASSWORD
    echo -n "$POSTGRES_PASSWORD" | gcloud secrets create sentinel3-db-password --data-file=-
    
    echo -e "${YELLOW}Enter Infura API key:${NC}"
    read -s INFURA_API_KEY
    echo -n "$INFURA_API_KEY" | gcloud secrets create infura-api-key --data-file=-
    
    echo -e "${GREEN}Secrets created!${NC}"
}

# ============================================================================
# Main Menu
# ============================================================================

echo "Select deployment option:"
echo "1) Cloud Run with GPU (Recommended - Simpler)"
echo "2) GKE with GPU (More control)"
echo "3) Setup Database (Cloud SQL)"
echo "4) Setup Redis (Memorystore)"
echo "5) Setup Secrets (Secret Manager)"
echo "6) Full Setup (All components)"
echo ""
read -p "Enter option (1-6): " option

case $option in
    1) setup_cloud_run ;;
    2) setup_gke ;;
    3) setup_database ;;
    4) setup_redis ;;
    5) setup_secrets ;;
    6)
        setup_secrets
        setup_database
        setup_redis
        setup_gke
        ;;
    *)
        echo -e "${RED}Invalid option${NC}"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}============================================${NC}"
echo -e "${GREEN}  Setup Complete!${NC}"
echo -e "${GREEN}============================================${NC}"
echo ""
echo "Next steps:"
echo "1. Update your DNS to point to the external IP"
echo "2. Configure SSL certificate"
echo "3. Update environment variables in the deployment"
echo ""
echo "Useful commands:"
echo "  kubectl get pods -n sentinel3          # Check pod status"
echo "  kubectl logs -f deployment/sentinel3-api -n sentinel3  # View logs"
echo "  kubectl get hpa -n sentinel3           # Check autoscaling"
