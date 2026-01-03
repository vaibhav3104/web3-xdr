# 🚀 Web3 XDR - Cloud Deployment Guide

## Quick Start

Choose your cloud provider:

| Provider | Service | Estimated Cost | Setup Time |
|----------|---------|----------------|------------|
| **AWS** | ECS Fargate + RDS | ~$150/month | 30 mins |
| **GCP** | Cloud Run + Cloud SQL | ~$100/month | 20 mins |
| **Kubernetes** | Any K8s cluster | Varies | 15 mins |

---

## 🔶 AWS Deployment (ECS Fargate)

### Prerequisites
- AWS CLI configured
- Terraform >= 1.0.0
- Docker

### Step 1: Configure Variables

```bash
cd deploy/aws/terraform
cp production.tfvars.example production.tfvars
# Edit production.tfvars with your values
```

### Step 2: Deploy Infrastructure

```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan -var-file="production.tfvars"

# Apply
terraform apply -var-file="production.tfvars"
```

### Step 3: Push Docker Image

```bash
# Get ECR login
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <ECR_URL>

# Build and push
docker build -t web3-xdr .
docker tag web3-xdr:latest <ECR_URL>/web3-xdr:latest
docker push <ECR_URL>/web3-xdr:latest

# Force new deployment
aws ecs update-service --cluster web3-xdr-cluster --service web3-xdr --force-new-deployment
```

### Step 4: Configure Secrets

```bash
# Store secrets in AWS Secrets Manager
aws secretsmanager create-secret --name web3-xdr/rpc --secret-string '{"infura_key":"YOUR_KEY"}'
aws secretsmanager create-secret --name web3-xdr/alerts --secret-string '{"telegram_token":"","slack_webhook":""}'
```

### Access Your Dashboard
```
http://<ALB_DNS_NAME>/frontend/index.html
```

---

## 🔵 GCP Deployment (Cloud Run)

### Prerequisites
- gcloud CLI configured
- Terraform >= 1.0.0

### Step 1: Configure Variables

```bash
cd deploy/gcp/terraform
cp production.tfvars.example production.tfvars
# Edit with your project ID
```

### Step 2: Deploy Infrastructure

```bash
# Login to GCP
gcloud auth application-default login

# Initialize and apply
terraform init
terraform apply -var-file="production.tfvars"
```

### Step 3: Push Docker Image

```bash
# Configure Docker for Artifact Registry
gcloud auth configure-docker us-central1-docker.pkg.dev

# Build and push
docker build -t web3-xdr .
docker tag web3-xdr us-central1-docker.pkg.dev/PROJECT_ID/web3-xdr/web3-xdr:latest
docker push us-central1-docker.pkg.dev/PROJECT_ID/web3-xdr/web3-xdr:latest

# Deploy to Cloud Run
gcloud run deploy web3-xdr \
  --image us-central1-docker.pkg.dev/PROJECT_ID/web3-xdr/web3-xdr:latest \
  --region us-central1 \
  --allow-unauthenticated
```

### Access Your Dashboard
```
https://<SERVICE_URL>/frontend/index.html
```

---

## ☸️ Kubernetes Deployment

### Prerequisites
- kubectl configured
- Kubernetes cluster (EKS, GKE, AKS, or self-managed)

### Step 1: Create Namespace and Secrets

```bash
# Create namespace
kubectl create namespace web3-xdr

# Create secrets (edit values first!)
kubectl create secret generic web3-xdr-secrets \
  --namespace web3-xdr \
  --from-literal=POSTGRES_HOST=your-db-host \
  --from-literal=POSTGRES_USER=xdr_admin \
  --from-literal=POSTGRES_PASSWORD=your-password \
  --from-literal=INFURA_API_KEY=your-key
```

### Step 2: Deploy with Kustomize

```bash
# For production
kubectl apply -k deploy/kubernetes/overlays/production

# Check status
kubectl get pods -n web3-xdr
kubectl get services -n web3-xdr
```

### Step 3: Configure Ingress

```bash
# Update ingress with your domain
kubectl edit ingress web3-xdr -n web3-xdr
```

---

## 🔒 Security Checklist

Before going to production:

- [ ] Enable HTTPS/TLS
- [ ] Configure WAF (AWS WAF / Cloud Armor)
- [ ] Set up VPC peering for database access
- [ ] Enable audit logging
- [ ] Configure backup retention
- [ ] Set up monitoring alerts
- [ ] Rotate secrets regularly
- [ ] Enable DDoS protection
- [ ] Configure rate limiting

---

## 📊 Monitoring

### AWS CloudWatch

```bash
# View logs
aws logs tail /ecs/web3-xdr --follow

# Create dashboard
aws cloudwatch put-dashboard --dashboard-name web3-xdr --dashboard-body file://monitoring/cloudwatch-dashboard.json
```

### GCP Cloud Monitoring

```bash
# View logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr" --limit 100
```

### Kubernetes (Prometheus + Grafana)

```bash
# Port forward Grafana
kubectl port-forward svc/grafana 3000:3000 -n monitoring
```

---

## 💰 Cost Optimization

### AWS
- Use Fargate Spot for non-critical workloads
- Enable RDS Reserved Instances for production
- Use S3 lifecycle policies for log archival

### GCP
- Use Cloud Run min instances = 0 for dev
- Use committed use discounts for Cloud SQL
- Enable Cloud Storage lifecycle policies

---

## 🆘 Troubleshooting

### Container won't start

```bash
# AWS
aws ecs describe-tasks --cluster web3-xdr-cluster --tasks <TASK_ID>

# GCP
gcloud run services logs read web3-xdr --region us-central1

# Kubernetes
kubectl logs -n web3-xdr deployment/web3-xdr
```

### Database connection issues

```bash
# Test connectivity
kubectl run -it --rm debug --image=postgres:15-alpine -- psql -h <DB_HOST> -U xdr_admin -d web3_xdr
```

### Health check failures

```bash
# Check health endpoint
curl -v http://<SERVICE_URL>/health
```

---

## 📞 Support

- **GitHub Issues**: Report bugs and feature requests
- **Documentation**: See /docs for detailed guides
- **Slack**: Join our community (if available)

