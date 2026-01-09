# Deploy Now - Complete Guide

**Status:** Ready to deploy bundled React + Python application ✅

---

## 🚀 Quick Deploy Options

### Option 1: Local Docker (Recommended for Testing)

**Prerequisites:**
- Docker Desktop installed and running
- 2GB RAM available

**Deploy:**
   ```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Start Docker Desktop first!
# Then run:
./deploy-local.sh
```

**Access:**
- War Room UI: http://localhost:9090/
- Health: http://localhost:9090/health
- Metrics: http://localhost:9090/metrics

---

### Option 2: Cloud Run (Production)

**Prerequisites:**
- Google Cloud SDK installed
- Project ID: `web3-xdr` (or set `GCP_PROJECT_ID`)
- Docker Desktop running

**Deploy:**
```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Set project (if different)
export GCP_PROJECT_ID="your-project-id"

# Deploy
./deploy-bundled.sh
```

**Result:**
- Service URL: `https://web3-xdr-worker-XXXXX.run.app`
- Auto-scaling: 1-10 instances
- Memory: 2GB per instance

---

### Option 3: Manual Docker Build

**If scripts don't work:**

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# 1. Build image
docker build -t web3-xdr:latest .

# 2. Run container
docker run -d \
  --name web3-xdr \
  -p 9090:9090 \
  -e RUNTIME_ENABLED=false \
  web3-xdr:latest

# 3. Check logs
docker logs -f web3-xdr

# 4. Access UI
open http://localhost:9090
```

---

## 📋 Pre-Deployment Checklist

### Before You Deploy

- [ ] Docker Desktop is installed
- [ ] Docker Desktop is **running** (check menu bar icon)
- [ ] You're in the project directory
- [ ] You have 2GB+ RAM available
- [ ] Port 9090 is not in use

**Check Docker:**
```bash
docker info
# Should show: Server Version: XX.X.X
```

**Check Port:**
```bash
lsof -i :9090
# Should be empty (or kill existing process)
```

---

## 🔧 Step-by-Step Manual Deployment

### Step 1: Start Docker

1. Open **Docker Desktop** application
2. Wait for "Docker Desktop is running" status
3. Verify: `docker info` works

### Step 2: Build Frontend

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr/frontend/war-room

# Install dependencies (if needed)
npm install

# Build
npm run build

# Verify
ls -la dist/
# Should see: index.html, assets/
```

### Step 3: Build Docker Image

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Build (this takes 5-10 minutes first time)
docker build -t web3-xdr:latest .

# Verify
docker images | grep web3-xdr
```

### Step 4: Run Container

```bash
# Stop any existing container
docker stop web3-xdr 2>/dev/null || true
docker rm web3-xdr 2>/dev/null || true

# Run new container
docker run -d \
  --name web3-xdr \
  -p 9090:9090 \
  -e RUNTIME_ENABLED=false \
  -e LOG_LEVEL=INFO \
  web3-xdr:latest

# Check if running
docker ps | grep web3-xdr
```

### Step 5: Verify Deployment

```bash
# Wait for startup (30 seconds)
sleep 30

# Test health
curl http://localhost:9090/health

# Test UI
curl http://localhost:9090/

# View logs
docker logs web3-xdr
```

### Step 6: Access UI

**Open browser:**
```bash
open http://localhost:9090
```

**Or manually navigate to:**
- http://localhost:9090

---

## 🐛 Troubleshooting

### Issue: Docker daemon not running

**Error:** `Cannot connect to the Docker daemon`

**Solution:**
1. Open Docker Desktop application
2. Wait for it to fully start (green icon in menu bar)
3. Run `docker info` to verify
4. Try deployment again

---

### Issue: Port 9090 already in use

**Error:** `bind: address already in use`

**Solution:**
```bash
# Find process using port 9090
lsof -i :9090

# Kill it
kill -9 <PID>

# Or use different port
docker run -p 9091:9090 ...
```

---

### Issue: Build fails on frontend

**Error:** `npm run build` fails

**Solution:**
```bash
cd frontend/war-room

# Clear cache
rm -rf node_modules dist

# Reinstall
npm install

# Try build again
npm run build
```

---

### Issue: Container starts but UI shows 404

**Error:** Blank page or "UI not found"

**Solution:**
```bash
# Check if static files exist in container
docker exec web3-xdr ls -la /app/static/

# Should see:
# - index.html
# - assets/

# If missing, rebuild:
docker build --no-cache -t web3-xdr:latest .
```

---

### Issue: Health check fails

**Error:** `curl http://localhost:9090/health` fails

**Solution:**
```bash
# Check if container is running
docker ps | grep web3-xdr

# Check logs for errors
docker logs web3-xdr

# Common issues:
# - Port binding failed
# - Python dependencies missing
# - Database connection error (ignore if RUNTIME_ENABLED=false)
```

---

## 🌐 Cloud Run Deployment

### Prerequisites

```bash
# Install gcloud CLI
# https://cloud.google.com/sdk/docs/install

# Login
gcloud auth login

# Set project
gcloud config set project web3-xdr

# Enable APIs
gcloud services enable run.googleapis.com
gcloud services enable containerregistry.googleapis.com
```

### Deploy to Cloud Run

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Option 1: Use script
./deploy-bundled.sh

# Option 2: Manual deploy
gcloud run deploy web3-xdr-worker \
  --source . \
  --region us-central1 \
  --platform managed \
  --port 9090 \
  --memory 2Gi \
  --cpu 2 \
  --allow-unauthenticated \
  --set-env-vars="RUNTIME_ENABLED=true"
```

### Get Service URL

```bash
gcloud run services describe web3-xdr-worker \
  --region us-central1 \
  --format 'value(status.url)'
```

---

## 📊 Monitoring

### View Logs (Local)

```bash
# Follow logs
docker logs -f web3-xdr

# Last 100 lines
docker logs --tail 100 web3-xdr

# With timestamps
docker logs -t web3-xdr
```

### View Logs (Cloud Run)

```bash
gcloud logging read \
  "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-worker" \
  --limit=50 \
  --format=json
```

### Check Metrics

**Local:**
```bash
curl http://localhost:9090/metrics
```

**Cloud Run:**
```bash
curl https://YOUR-SERVICE-URL.run.app/metrics
```

---

## 🔒 Security Notes

### Local Development
- Uses `RUNTIME_ENABLED=false` by default
- No external dependencies required
- Safe for testing

### Production (Cloud Run)
- Set `RUNTIME_ENABLED=true` for full features
- Configure secrets in Secret Manager:
  - `web3-xdr-database-url`
  - `web3-xdr-redis-url`
  - `web3-xdr-bloxroute-auth` (optional)

---

## 📈 Performance

### Build Time
- First build: 5-10 minutes
- Subsequent builds: 2-3 minutes (cached layers)

### Image Size
- Target: < 500MB
- Check: `docker images web3-xdr:latest`

### Startup Time
- Local: 5-10 seconds
- Cloud Run: 10-30 seconds (cold start)

---

## ✅ Success Criteria

After deployment, verify:

- [ ] Container is running: `docker ps`
- [ ] Health check passes: `curl http://localhost:9090/health`
- [ ] UI loads: Open http://localhost:9090 in browser
- [ ] Static assets load (check browser DevTools Network tab)
- [ ] No console errors in browser
- [ ] React Router works (refresh any route)
- [ ] WebSocket connects (if enabled)

---

## 🎯 Next Steps

### After Local Deployment

1. **Test the UI:**
   - Navigate to different routes
   - Check WebSocket connection
   - Verify metrics endpoint

2. **Check logs:**
   ```bash
   docker logs web3-xdr
   ```

3. **Stop when done:**
   ```bash
   docker stop web3-xdr
   docker rm web3-xdr
   ```

### After Cloud Run Deployment

1. **Get URL:**
   ```bash
   gcloud run services describe web3-xdr-worker \
     --region us-central1 \
     --format 'value(status.url)'
   ```

2. **Test endpoints:**
   ```bash
   curl https://YOUR-URL/health
   curl https://YOUR-URL/
   ```

3. **Monitor:**
   - Cloud Run Console: https://console.cloud.google.com/run
   - View logs, metrics, and scaling

---

## 🆘 Getting Help

### Check Logs

```bash
# Local
docker logs web3-xdr

# Cloud Run
gcloud logging read "resource.type=cloud_run_revision" --limit=50
```

### Common Commands

```bash
# Restart container
docker restart web3-xdr

# Rebuild from scratch
docker build --no-cache -t web3-xdr:latest .

# Shell into container
docker exec -it web3-xdr /bin/bash

# Remove all containers
docker stop $(docker ps -aq)
docker rm $(docker ps -aq)
```

---

## 📞 Quick Reference

| Command | Purpose |
|---------|---------|
| `./deploy-local.sh` | Deploy locally |
| `./deploy-bundled.sh` | Deploy to Cloud Run |
| `docker ps` | List running containers |
| `docker logs web3-xdr` | View logs |
| `docker stop web3-xdr` | Stop container |
| `open http://localhost:9090` | Open UI |

---

**Ready to deploy!** 🚀

Choose your deployment option above and follow the steps. Start with local deployment to test, then move to Cloud Run for production.
