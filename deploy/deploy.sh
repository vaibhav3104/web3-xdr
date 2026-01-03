#!/bin/bash
# =============================================================================
# Web3 XDR - Quick Deploy Script
# =============================================================================
# Usage:
#   ./deploy.sh aws       # Deploy to AWS ECS
#   ./deploy.sh gcp       # Deploy to GCP Cloud Run
#   ./deploy.sh k8s       # Deploy to Kubernetes
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Banner
print_banner() {
    echo ""
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           🛡️  Web3 XDR - Cloud Deployment                     ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo ""
}

# Check prerequisites
check_prerequisites() {
    local provider=$1
    
    log_info "Checking prerequisites for $provider..."
    
    # Docker is always required
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        exit 1
    fi
    
    case $provider in
        aws)
            if ! command -v aws &> /dev/null; then
                log_error "AWS CLI is not installed"
                exit 1
            fi
            if ! command -v terraform &> /dev/null; then
                log_error "Terraform is not installed"
                exit 1
            fi
            ;;
        gcp)
            if ! command -v gcloud &> /dev/null; then
                log_error "gcloud CLI is not installed"
                exit 1
            fi
            ;;
        k8s)
            if ! command -v kubectl &> /dev/null; then
                log_error "kubectl is not installed"
                exit 1
            fi
            ;;
    esac
    
    log_success "All prerequisites met!"
}

# Build Docker image
build_image() {
    log_info "Building Docker image..."
    cd "$PROJECT_ROOT"
    docker build -t web3-xdr:latest .
    log_success "Image built successfully!"
}

# Deploy to AWS
deploy_aws() {
    log_info "Deploying to AWS ECS..."
    
    # Check for AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        log_error "AWS credentials not configured. Run 'aws configure'"
        exit 1
    fi
    
    AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
    AWS_REGION=${AWS_REGION:-us-east-1}
    ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"
    
    log_info "AWS Account: $AWS_ACCOUNT_ID"
    log_info "Region: $AWS_REGION"
    
    # Create ECR repository if not exists
    aws ecr describe-repositories --repository-names web3-xdr &> /dev/null || \
        aws ecr create-repository --repository-name web3-xdr
    
    # Login to ECR
    log_info "Logging into ECR..."
    aws ecr get-login-password --region $AWS_REGION | \
        docker login --username AWS --password-stdin $ECR_REGISTRY
    
    # Tag and push image
    log_info "Pushing image to ECR..."
    docker tag web3-xdr:latest "${ECR_REGISTRY}/web3-xdr:latest"
    docker push "${ECR_REGISTRY}/web3-xdr:latest"
    
    # Deploy with Terraform
    cd "$SCRIPT_DIR/aws/terraform"
    
    if [ ! -f "production.tfvars" ]; then
        log_warning "production.tfvars not found. Creating from example..."
        cat > production.tfvars << EOF
aws_region = "$AWS_REGION"
environment = "production"
EOF
    fi
    
    terraform init
    terraform apply -var-file="production.tfvars" -auto-approve
    
    # Get outputs
    ALB_DNS=$(terraform output -raw alb_dns_name 2>/dev/null || echo "pending")
    
    log_success "AWS deployment complete!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  🎉 Deployment Successful!                                     ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  Dashboard: http://${ALB_DNS}/frontend/index.html              ║"
    echo "║  API Docs:  http://${ALB_DNS}/api/docs                         ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
}

# Deploy to GCP
deploy_gcp() {
    log_info "Deploying to GCP Cloud Run..."
    
    # Check for GCP credentials
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | head -1 &> /dev/null; then
        log_error "GCP not authenticated. Run 'gcloud auth login'"
        exit 1
    fi
    
    GCP_PROJECT=$(gcloud config get-value project 2>/dev/null)
    GCP_REGION=${GCP_REGION:-us-central1}
    
    if [ -z "$GCP_PROJECT" ]; then
        log_error "GCP project not set. Run 'gcloud config set project PROJECT_ID'"
        exit 1
    fi
    
    log_info "GCP Project: $GCP_PROJECT"
    log_info "Region: $GCP_REGION"
    
    # Enable required APIs
    log_info "Enabling required APIs..."
    gcloud services enable run.googleapis.com artifactregistry.googleapis.com
    
    # Create Artifact Registry repository
    gcloud artifacts repositories create web3-xdr \
        --repository-format=docker \
        --location=$GCP_REGION 2>/dev/null || true
    
    # Configure Docker
    log_info "Configuring Docker for Artifact Registry..."
    gcloud auth configure-docker ${GCP_REGION}-docker.pkg.dev --quiet
    
    # Tag and push image
    log_info "Pushing image to Artifact Registry..."
    ARTIFACT_REGISTRY="${GCP_REGION}-docker.pkg.dev/${GCP_PROJECT}/web3-xdr"
    docker tag web3-xdr:latest "${ARTIFACT_REGISTRY}/web3-xdr:latest"
    docker push "${ARTIFACT_REGISTRY}/web3-xdr:latest"
    
    # Deploy to Cloud Run
    log_info "Deploying to Cloud Run..."
    gcloud run deploy web3-xdr \
        --image "${ARTIFACT_REGISTRY}/web3-xdr:latest" \
        --region $GCP_REGION \
        --platform managed \
        --allow-unauthenticated \
        --memory 2Gi \
        --cpu 2 \
        --min-instances 1 \
        --max-instances 10 \
        --set-env-vars "ENVIRONMENT=production,LOG_LEVEL=INFO"
    
    # Get service URL
    SERVICE_URL=$(gcloud run services describe web3-xdr --region $GCP_REGION --format 'value(status.url)')
    
    log_success "GCP deployment complete!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  🎉 Deployment Successful!                                     ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  Dashboard: ${SERVICE_URL}/frontend/index.html                 ║"
    echo "║  API Docs:  ${SERVICE_URL}/api/docs                            ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
}

# Deploy to Kubernetes
deploy_k8s() {
    log_info "Deploying to Kubernetes..."
    
    # Check kubectl context
    CONTEXT=$(kubectl config current-context 2>/dev/null)
    if [ -z "$CONTEXT" ]; then
        log_error "No Kubernetes context configured"
        exit 1
    fi
    
    log_info "Using Kubernetes context: $CONTEXT"
    
    # Create namespace
    kubectl create namespace web3-xdr 2>/dev/null || true
    
    # Apply base manifests
    log_info "Applying Kubernetes manifests..."
    kubectl apply -k "$SCRIPT_DIR/kubernetes/base"
    
    # Wait for deployment
    log_info "Waiting for deployment to be ready..."
    kubectl rollout status deployment/web3-xdr -n web3-xdr --timeout=300s
    
    # Get service info
    SERVICE_IP=$(kubectl get svc web3-xdr -n web3-xdr -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || echo "pending")
    
    log_success "Kubernetes deployment complete!"
    echo ""
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║  🎉 Deployment Successful!                                     ║"
    echo "╠════════════════════════════════════════════════════════════════╣"
    echo "║  Pods:      kubectl get pods -n web3-xdr                       ║"
    echo "║  Services:  kubectl get svc -n web3-xdr                        ║"
    echo "║  Logs:      kubectl logs -n web3-xdr -l app=web3-xdr           ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
}

# Main
main() {
    print_banner
    
    if [ $# -lt 1 ]; then
        echo "Usage: $0 <provider>"
        echo ""
        echo "Providers:"
        echo "  aws    Deploy to AWS ECS Fargate"
        echo "  gcp    Deploy to GCP Cloud Run"
        echo "  k8s    Deploy to Kubernetes"
        echo ""
        exit 1
    fi
    
    PROVIDER=$1
    
    check_prerequisites $PROVIDER
    build_image
    
    case $PROVIDER in
        aws)
            deploy_aws
            ;;
        gcp)
            deploy_gcp
            ;;
        k8s)
            deploy_k8s
            ;;
        *)
            log_error "Unknown provider: $PROVIDER"
            exit 1
            ;;
    esac
}

main "$@"

