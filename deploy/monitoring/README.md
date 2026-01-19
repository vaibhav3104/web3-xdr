# Sentinel3 Monitoring Stack

Grafana + Prometheus monitoring for Sentinel3 Web3-XDR.

## Quick Start

### Option 1: Docker Compose (Local)

```bash
cd deploy/monitoring
docker-compose up -d
```

Access:
- **Grafana**: http://localhost:3000 (admin / sentinel3admin)
- **Prometheus**: http://localhost:9090

### Option 2: Google Cloud Monitoring

Use Google Cloud's built-in monitoring for Cloud Run services.

1. Go to [Cloud Monitoring](https://console.cloud.google.com/monitoring)
2. Create a new dashboard
3. Add charts for:
   - Cloud Run request count
   - Cloud Run latency
   - Cloud Run memory usage
   - Cloud Run CPU usage

## Dashboards

### Sentinel3 Overview

Main dashboard showing:
- Active Incidents
- Critical Alerts
- Total Events
- Blocks Scanned
- Events by Chain
- Events by Severity
- GPU Memory Usage
- ML Inference Time
- ML Model Accuracy

### Metrics Available

| Metric | Description |
|--------|-------------|
| `sentinel3_events_ingested_total` | Total events ingested |
| `sentinel3_rpc_latency_seconds` | RPC latency |
| `sentinel3_head_lag_blocks` | Blocks behind chain head |
| `sentinel3_worker_uptime_seconds` | Worker uptime |
| `sentinel3_runtime_simulations_total` | Simulations run |
| `sentinel3_predicted_incidents_total` | Predicted incidents |

## API Endpoints for Monitoring

| Endpoint | Description |
|----------|-------------|
| `/metrics` | Prometheus metrics |
| `/health` | Health check |
| `/api/stats` | System statistics |
| `/api/ml/status` | ML system status |
| `/api/ml/model-info` | Model details |
| `/ws/status` | WebSocket connections |

## Alerts

Configure alerts in Grafana for:

1. **High Incident Rate**: > 5 incidents in 1 hour
2. **ML Latency**: > 500ms inference time
3. **GPU Memory**: > 80% usage
4. **RPC Errors**: > 10 errors in 5 minutes
5. **Service Down**: Health check fails

## Cloud Run Monitoring

View Cloud Run metrics:

```bash
# List services
gcloud run services list --region=us-central1

# View logs
gcloud run services logs read sentinel3 --region=us-central1 --limit=100

# View metrics
gcloud monitoring dashboards list
```

## Cost Monitoring

Monitor GPU costs:

```bash
# View billing
gcloud billing accounts list

# Export billing data
gcloud billing export create sentinel3-billing \
  --billing-account=YOUR_BILLING_ACCOUNT \
  --bigquery-dataset=billing_export
```

## Troubleshooting

### Grafana can't connect to Prometheus
- Check Prometheus is running: `docker-compose ps`
- Verify network: `docker network ls`

### No metrics showing
- Check `/metrics` endpoint returns data
- Verify Prometheus scrape config
- Check service is accessible

### High memory usage
- GPU models use ~2-3GB
- Reduce batch size if needed
- Enable auto-scaling
