# Sentinel3 - Google Cloud Deployment

Deploy Sentinel3 on Google Cloud Platform with GPU acceleration for the ML transformer model.

## 🚀 Quick Start

### Prerequisites

1. **Google Cloud Account** with billing enabled
2. **gcloud CLI** installed and authenticated
3. **GPU Quota** - Request quota increase for GPUs in your region

```bash
# Install gcloud CLI
curl https://sdk.cloud.google.com | bash

# Authenticate
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
```

### Deploy with One Command

```bash
cd deploy/gcloud
chmod +x setup-gcloud.sh
./setup-gcloud.sh
```

## 📋 Deployment Options

### Option 1: Cloud Run with GPU (Recommended)

Serverless deployment with automatic scaling. Best for most use cases.

**GPU Type:** NVIDIA L4 (24GB VRAM)  
**Cost:** ~$0.50/hour when running

```bash
# Build and deploy
gcloud builds submit --config=cloudbuild.yaml

# Or manually
gcloud run deploy sentinel3-api \
  --image gcr.io/$PROJECT_ID/sentinel3-gpu:latest \
  --region us-central1 \
  --gpu 1 \
  --gpu-type nvidia-l4 \
  --memory 16Gi \
  --cpu 4
```

### Option 2: GKE with GPU (More Control)

Kubernetes deployment for full control over scaling and resources.

**GPU Type:** NVIDIA Tesla T4 (16GB VRAM)  
**Cost:** ~$0.35/hour per GPU node

```bash
# Create cluster with GPU nodes
gcloud container clusters create sentinel3-cluster \
  --zone us-central1-a \
  --num-nodes 2

# Add GPU node pool
gcloud container node-pools create gpu-pool \
  --cluster sentinel3-cluster \
  --accelerator type=nvidia-tesla-t4,count=1 \
  --num-nodes 1

# Deploy
kubectl apply -f gke-deployment.yaml
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ML_MODEL_TYPE` | Model type (transformer, mlp, cnn) | `transformer` |
| `ML_DEVICE` | Device (cuda, cpu, auto) | `cuda` |
| `POSTGRES_HOST` | Database host | - |
| `REDIS_URL` | Redis connection URL | - |

### Secrets (Secret Manager)

```bash
# Create secrets
echo -n "your_password" | gcloud secrets create sentinel3-db-password --data-file=-
echo -n "your_infura_key" | gcloud secrets create infura-api-key --data-file=-
```

## 💰 Cost Estimation

### Cloud Run with GPU

| Component | Cost/Hour | Cost/Month (24/7) |
|-----------|-----------|-------------------|
| NVIDIA L4 GPU | $0.50 | ~$360 |
| 4 vCPU + 16GB RAM | $0.20 | ~$144 |
| **Total** | **$0.70** | **~$504** |

*With autoscaling to 0, costs only when processing*

### GKE with GPU

| Component | Cost/Hour | Cost/Month (24/7) |
|-----------|-----------|-------------------|
| NVIDIA T4 GPU Node | $0.35 | ~$252 |
| Standard Nodes (2x) | $0.10 | ~$144 |
| Load Balancer | $0.025 | ~$18 |
| **Total** | **$0.475** | **~$414** |

## 📊 GPU Options

| GPU | VRAM | Use Case | Cost/Hour |
|-----|------|----------|-----------|
| NVIDIA T4 | 16GB | Development, small scale | $0.35 |
| NVIDIA L4 | 24GB | Production, medium scale | $0.50 |
| NVIDIA A100 | 40GB | High throughput | $2.93 |
| NVIDIA H100 | 80GB | Maximum performance | $8.00+ |

**Recommendation:** NVIDIA L4 for best price/performance ratio.

## 🔍 Monitoring

### View Logs

```bash
# Cloud Run
gcloud run services logs read sentinel3-api --region us-central1

# GKE
kubectl logs -f deployment/sentinel3-api -n sentinel3
```

### GPU Utilization

```bash
# In pod
nvidia-smi

# Or via kubectl
kubectl exec -it <pod-name> -n sentinel3 -- nvidia-smi
```

### Metrics

Cloud Monitoring dashboards are automatically created. View at:
https://console.cloud.google.com/monitoring

## 🛠️ Troubleshooting

### GPU Not Detected

```bash
# Check if GPU driver is installed
kubectl get pods -n kube-system | grep nvidia

# Check GPU availability
kubectl describe nodes | grep nvidia.com/gpu
```

### Out of Memory

Increase memory limit or use a larger GPU:

```yaml
resources:
  limits:
    memory: "32Gi"
    nvidia.com/gpu: "1"
```

### Slow Inference

1. Check GPU is being used: `nvidia-smi`
2. Verify `ML_DEVICE=cuda` is set
3. Consider using A100 for higher throughput

## 📁 Files

| File | Description |
|------|-------------|
| `Dockerfile.gpu` | Docker image with CUDA support |
| `cloudbuild.yaml` | Cloud Build configuration |
| `gke-deployment.yaml` | Kubernetes manifests |
| `setup-gcloud.sh` | Automated setup script |

## 🔗 Useful Links

- [Cloud Run GPU Documentation](https://cloud.google.com/run/docs/configuring/services/gpu)
- [GKE GPU Documentation](https://cloud.google.com/kubernetes-engine/docs/how-to/gpus)
- [GPU Pricing](https://cloud.google.com/compute/gpus-pricing)
- [Request GPU Quota](https://cloud.google.com/compute/quotas)
