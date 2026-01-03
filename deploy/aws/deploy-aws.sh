#!/bin/bash
# =============================================================================
# AWS DEPLOYMENT SCRIPT for Web3 XDR
# =============================================================================
# 
# This script deploys Web3 XDR to AWS using:
# - ECR (Elastic Container Registry) for Docker images
# - ECS Fargate for serverless container hosting
# - RDS PostgreSQL for database
# - Application Load Balancer for traffic
#
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - Docker installed and running
# - Terraform installed (optional, for infrastructure)
#
# Usage:
#   ./deploy-aws.sh [environment]
#   ./deploy-aws.sh production
#   ./deploy-aws.sh staging
#
# =============================================================================

set -e

# Configuration
ENVIRONMENT=${1:-production}
AWS_REGION=${AWS_REGION:-us-east-1}
APP_NAME="web3-xdr"
ECR_REPO_NAME="${APP_NAME}-${ENVIRONMENT}"

echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║               🚀 AWS DEPLOYMENT - Web3 XDR                            ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Environment: ${ENVIRONMENT}"
echo "Region:      ${AWS_REGION}"
echo ""

# Get AWS account ID
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
ECR_REGISTRY="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com"

echo "AWS Account: ${AWS_ACCOUNT_ID}"
echo "ECR Registry: ${ECR_REGISTRY}"
echo ""

# =============================================================================
# Step 1: Create ECR Repository (if not exists)
# =============================================================================
echo "📦 Step 1: Setting up ECR repository..."

aws ecr describe-repositories --repository-names ${ECR_REPO_NAME} --region ${AWS_REGION} 2>/dev/null || \
aws ecr create-repository \
    --repository-name ${ECR_REPO_NAME} \
    --region ${AWS_REGION} \
    --image-scanning-configuration scanOnPush=true \
    --encryption-configuration encryptionType=AES256

echo "✅ ECR repository ready: ${ECR_REPO_NAME}"

# =============================================================================
# Step 2: Build and Push Docker Image
# =============================================================================
echo ""
echo "🔨 Step 2: Building Docker image..."

cd "$(dirname "$0")/../.."

# Login to ECR
aws ecr get-login-password --region ${AWS_REGION} | \
    docker login --username AWS --password-stdin ${ECR_REGISTRY}

# Build image
IMAGE_TAG="${ECR_REGISTRY}/${ECR_REPO_NAME}:latest"
docker build -t ${IMAGE_TAG} .

# Also tag with git commit for versioning
GIT_COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
docker tag ${IMAGE_TAG} "${ECR_REGISTRY}/${ECR_REPO_NAME}:${GIT_COMMIT}"

# Push to ECR
echo ""
echo "📤 Pushing image to ECR..."
docker push ${IMAGE_TAG}
docker push "${ECR_REGISTRY}/${ECR_REPO_NAME}:${GIT_COMMIT}"

echo "✅ Image pushed: ${IMAGE_TAG}"

# =============================================================================
# Step 3: Create/Update ECS Task Definition
# =============================================================================
echo ""
echo "📝 Step 3: Creating ECS task definition..."

TASK_DEF=$(cat <<EOF
{
    "family": "${APP_NAME}-${ENVIRONMENT}",
    "networkMode": "awsvpc",
    "requiresCompatibilities": ["FARGATE"],
    "cpu": "512",
    "memory": "1024",
    "executionRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskExecutionRole",
    "taskRoleArn": "arn:aws:iam::${AWS_ACCOUNT_ID}:role/ecsTaskRole",
    "containerDefinitions": [
        {
            "name": "${APP_NAME}",
            "image": "${IMAGE_TAG}",
            "essential": true,
            "portMappings": [
                {
                    "containerPort": 8080,
                    "protocol": "tcp"
                }
            ],
            "environment": [
                {"name": "ENVIRONMENT", "value": "${ENVIRONMENT}"},
                {"name": "AWS_REGION", "value": "${AWS_REGION}"},
                {"name": "POSTGRES_ENABLED", "value": "true"}
            ],
            "secrets": [
                {
                    "name": "POSTGRES_HOST",
                    "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${APP_NAME}/${ENVIRONMENT}/db:host::"
                },
                {
                    "name": "POSTGRES_PASSWORD",
                    "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${APP_NAME}/${ENVIRONMENT}/db:password::"
                },
                {
                    "name": "OPENAI_API_KEY",
                    "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${APP_NAME}/${ENVIRONMENT}/api-keys:openai::"
                },
                {
                    "name": "INFURA_API_KEY",
                    "valueFrom": "arn:aws:secretsmanager:${AWS_REGION}:${AWS_ACCOUNT_ID}:secret:${APP_NAME}/${ENVIRONMENT}/api-keys:infura::"
                }
            ],
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-group": "/ecs/${APP_NAME}-${ENVIRONMENT}",
                    "awslogs-region": "${AWS_REGION}",
                    "awslogs-stream-prefix": "ecs"
                }
            },
            "healthCheck": {
                "command": ["CMD-SHELL", "curl -f http://localhost:8080/health || exit 1"],
                "interval": 30,
                "timeout": 5,
                "retries": 3,
                "startPeriod": 60
            }
        }
    ]
}
EOF
)

# Create CloudWatch log group
aws logs create-log-group --log-group-name "/ecs/${APP_NAME}-${ENVIRONMENT}" --region ${AWS_REGION} 2>/dev/null || true

# Register task definition
echo "${TASK_DEF}" > /tmp/task-def.json
aws ecs register-task-definition --cli-input-json file:///tmp/task-def.json --region ${AWS_REGION}

echo "✅ Task definition registered"

# =============================================================================
# Step 4: Create/Update ECS Service
# =============================================================================
echo ""
echo "🚀 Step 4: Deploying ECS service..."

CLUSTER_NAME="${APP_NAME}-cluster-${ENVIRONMENT}"
SERVICE_NAME="${APP_NAME}-service-${ENVIRONMENT}"

# Check if cluster exists
aws ecs describe-clusters --clusters ${CLUSTER_NAME} --region ${AWS_REGION} 2>/dev/null | grep -q "ACTIVE" || \
aws ecs create-cluster --cluster-name ${CLUSTER_NAME} --region ${AWS_REGION}

# Check if service exists and update or create
if aws ecs describe-services --cluster ${CLUSTER_NAME} --services ${SERVICE_NAME} --region ${AWS_REGION} 2>/dev/null | grep -q "ACTIVE"; then
    echo "Updating existing service..."
    aws ecs update-service \
        --cluster ${CLUSTER_NAME} \
        --service ${SERVICE_NAME} \
        --task-definition "${APP_NAME}-${ENVIRONMENT}" \
        --force-new-deployment \
        --region ${AWS_REGION}
else
    echo "Creating new service..."
    echo "⚠️  First deployment requires manual VPC/subnet/security group configuration"
    echo "   Use the Terraform templates in deploy/aws/terraform/ for full infrastructure setup"
fi

echo "✅ Deployment initiated"

# =============================================================================
# Summary
# =============================================================================
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════╗"
echo "║                    ✅ DEPLOYMENT COMPLETE                              ║"
echo "╚═══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "📦 ECR Image:    ${IMAGE_TAG}"
echo "📋 Task Family:  ${APP_NAME}-${ENVIRONMENT}"
echo "🏗️  Cluster:      ${CLUSTER_NAME}"
echo "🚀 Service:      ${SERVICE_NAME}"
echo ""
echo "Next steps:"
echo "  1. Configure secrets in AWS Secrets Manager"
echo "  2. Set up VPC, subnets, and security groups (use Terraform)"
echo "  3. Configure Application Load Balancer"
echo "  4. Set up DNS and SSL certificate"
echo ""
echo "View logs:"
echo "  aws logs tail /ecs/${APP_NAME}-${ENVIRONMENT} --follow"
echo ""

