# ☁️ Cloud Deployment Guide for Web3 XDR

This guide covers deploying Web3 XDR to production cloud environments.

## 📋 Deployment Options

| Platform | Best For | Estimated Cost | Setup Time |
|----------|----------|----------------|------------|
| **AWS ECS Fargate** | Enterprise, high availability | $50-200/month | 30-60 min |
| **GCP Cloud Run** | Startups, auto-scaling | $20-100/month | 15-30 min |
| **Kubernetes** | Full control, multi-cloud | $100-500/month | 60-120 min |

---

## 🚀 Option 1: GCP Cloud Run (Recommended for Quick Start)

### Prerequisites
```bash
# Install gcloud CLI
brew install google-cloud-sdk  # macOS
# or download from: https://cloud.google.com/sdk/install

# Login and set project
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Deploy
```bash
cd deploy/gcp
chmod +x deploy-gcp.sh
./deploy-gcp.sh production
```

### Configure Secrets
```bash
# Add your API keys
echo "your-openai-key" | gcloud secrets versions add web3-xdr-openai-api-key --data-file=-
echo "your-infura-key" | gcloud secrets versions add web3-xdr-infura-api-key --data-file=-
echo "your-jwt-secret" | gcloud secrets versions add web3-xdr-jwt-secret --data-file=-
```

### Result
- **URL**: `https://web3-xdr-production-xxxxx.run.app`
- **Auto-scaling**: 1-10 instances
- **SSL**: Automatic

---

## 🚀 Option 2: AWS ECS Fargate

### Prerequisites
```bash
# Install AWS CLI
brew install awscli  # macOS
aws configure  # Enter your credentials
```

### Deploy
```bash
cd deploy/aws
chmod +x deploy-aws.sh
./deploy-aws.sh production
```

### Configure Secrets (AWS Secrets Manager)
```bash
# Create secrets
aws secretsmanager create-secret \
    --name web3-xdr/production/api-keys \
    --secret-string '{"openai":"sk-xxx","infura":"xxx"}'
```

### Full Infrastructure (Terraform)
```bash
cd deploy/aws/terraform
terraform init
terraform plan
terraform apply
```

---

## 🔐 Required Secrets

| Secret | Description | Required |
|--------|-------------|----------|
| `INFURA_API_KEY` | Blockchain RPC access | ✅ Yes |
| `OPENAI_API_KEY` | AI incident analysis | Optional |
| `JWT_SECRET_KEY` | Auth token signing | ✅ Yes |
| `POSTGRES_PASSWORD` | Database password | ✅ Yes |
| `TELEGRAM_BOT_TOKEN` | Alert notifications | Optional |

---

## 📊 Environment Variables

```bash
# Required
ENVIRONMENT=production
POSTGRES_ENABLED=true
POSTGRES_HOST=your-db-host
POSTGRES_PORT=5432
POSTGRES_USER=xdr
POSTGRES_DB=web3_xdr

# Optional - AI Analysis
OPENAI_API_KEY=sk-xxx
# or
ANTHROPIC_API_KEY=sk-ant-xxx

# Optional - Alerting
TELEGRAM_BOT_TOKEN=xxx
TELEGRAM_CHANNEL_ID=-100xxx
```

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         CLOUD DEPLOYMENT                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐      │
│   │   Client    │────▶│ Load        │────▶│   Web3 XDR  │      │
│   │  (Browser)  │     │ Balancer    │     │  Container  │      │
│   └─────────────┘     └─────────────┘     └──────┬──────┘      │
│                                                   │              │
│                              ┌────────────────────┼──────┐      │
│                              │                    │      │      │
│                              ▼                    ▼      ▼      │
│                       ┌──────────┐         ┌─────────┐  ┌────┐ │
│                       │ PostgreSQL│         │ Secrets │  │Logs│ │
│                       │ (RDS/SQL) │         │ Manager │  │    │ │
│                       └──────────┘         └─────────┘  └────┘ │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 💰 Cost Estimation

### GCP Cloud Run
| Resource | Specification | Cost/Month |
|----------|--------------|------------|
| Cloud Run | 1 vCPU, 1GB RAM | ~$20-50 |
| Cloud SQL | db-f1-micro | ~$10-20 |
| Secrets | 5 secrets | ~$1 |
| **Total** | | **~$31-71** |

### AWS ECS Fargate
| Resource | Specification | Cost/Month |
|----------|--------------|------------|
| Fargate | 0.5 vCPU, 1GB RAM | ~$30-60 |
| RDS | db.t3.micro | ~$15-30 |
| ALB | Application LB | ~$20 |
| Secrets | 5 secrets | ~$2 |
| **Total** | | **~$67-112** |

---

## 🔄 CI/CD Pipeline

### GitHub Actions (already configured)
```yaml
# .github/workflows/deploy.yml
# Triggers on push to main branch
# Deploys to configured cloud platform
```

### Manual Deployment
```bash
# GCP
./deploy/gcp/deploy-gcp.sh production

# AWS
./deploy/aws/deploy-aws.sh production
```

---

## 📈 Monitoring in Production

### Cloud Run
```bash
# View logs
gcloud run services logs read web3-xdr-production --region=us-central1

# Monitor
open https://console.cloud.google.com/run
```

### AWS
```bash
# View logs
aws logs tail /ecs/web3-xdr-production --follow

# Monitor
open https://console.aws.amazon.com/ecs
```

### Grafana Dashboard
The deployment includes Prometheus metrics at `/metrics`. Connect to Grafana Cloud or deploy Grafana alongside for visualization.

---

## 🆘 Troubleshooting

### Container won't start
```bash
# Check logs
gcloud run services logs read SERVICE_NAME --region=REGION
# or
aws logs tail /ecs/TASK_NAME --follow
```

### Database connection failed
1. Verify secrets are set correctly
2. Check VPC/network configuration
3. Verify Cloud SQL/RDS instance is running

### AI analysis not working
1. Check OPENAI_API_KEY or ANTHROPIC_API_KEY is set
2. Verify API key has sufficient credits
3. Check `/api/ai/status` endpoint

---

## 📞 Support

For deployment issues:
1. Check logs first
2. Verify all secrets are configured
3. Ensure APIs are enabled (GCP) or services created (AWS)

Happy deploying! 🚀

