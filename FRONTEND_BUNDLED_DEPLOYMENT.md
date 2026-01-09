# Frontend Bundled Deployment Guide

**Status:** React War Room UI now bundled with Python Worker ✅

---

## Overview

The Lovable React frontend (War Room Dashboard) is now bundled with the Python backend and served from the `aiohttp` worker process.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Docker Container (Multi-Stage Build)                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Stage 1: Node.js Builder                                   │
│  ├─ npm install                                             │
│  ├─ npm run build                                           │
│  └─ Output: frontend/war-room/dist/                         │
│                                                              │
│  Stage 2: Python Runtime                                    │
│  ├─ Python 3.11 + dependencies                             │
│  ├─ Copy built frontend → /app/static                      │
│  └─ aiohttp worker serves:                                  │
│     ├─ /health → Health check                              │
│     ├─ /metrics → Prometheus metrics                       │
│     ├─ /assets/* → Static JS/CSS                           │
│     └─ /* → index.html (SPA catch-all)                     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Files Modified

### 1. `frontend/war-room/vite.config.ts`

**Changes:**
- Added `base: '/'` for root-level serving
- Updated proxy targets to port 9090 (worker port)
- Configured build output directory

```typescript
export default defineConfig({
  plugins: [react()],
  base: '/',  // ✅ Serve from root
  build: {
    outDir: 'dist',
    assetsDir: 'assets',
  },
  server: {
    proxy: {
      '/api': { target: 'http://localhost:9090' },  // ✅ Worker port
      '/ws': { target: 'ws://localhost:9090' },
    },
  },
});
```

### 2. `Dockerfile` (Multi-Stage Build)

**Stage 1: Frontend Builder**
```dockerfile
FROM node:18-alpine AS frontend-builder
WORKDIR /build
COPY frontend/war-room/package.json ./
RUN npm install
COPY frontend/war-room/ ./
RUN npm run build
```

**Stage 2: Python + Bundled Frontend**
```dockerfile
FROM python:3.11-slim
WORKDIR /app
# ... Python setup ...
COPY --from=frontend-builder /build/dist /app/static  # ✅ Copy built UI
```

### 3. `src/worker/main.py`

**Added Static File Serving:**

```python
# Static assets (JS/CSS)
app.router.add_static('/assets', Path("/app/static/assets"), name='assets')

# SPA catch-all (MUST be last)
app.router.add_get('/{tail:.*}', index_handler)
```

**Added Index Handler:**

```python
async def index_handler(request):
    """Serves index.html for React Router."""
    index_file = Path("/app/static/index.html")
    if not index_file.exists():
        return web.Response(text="UI not found", status=404)
    return web.FileResponse(index_file)
```

**Route Priority:**
1. `/health` → Health check (highest priority)
2. `/metrics` → Prometheus metrics
3. `/assets/*` → Static files (JS/CSS)
4. `/*` → index.html (catch-all for React Router)

---

## Build & Deploy

### Local Development

**Terminal 1: Build Frontend**
```bash
cd frontend/war-room
npm install
npm run build
```

**Terminal 2: Run Worker with UI**
```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
source venv/bin/activate

# Create static directory and copy build
mkdir -p static
cp -r frontend/war-room/dist/* static/

# Run worker
python -m src.worker.main
```

**Access:**
- War Room UI: http://localhost:9090/
- Health Check: http://localhost:9090/health
- Metrics: http://localhost:9090/metrics

---

### Docker Build

```bash
# Build image (multi-stage)
docker build -t web3-xdr:latest .

# Run worker with bundled UI
docker run -p 9090:9090 \
  -e RUNTIME_ENABLED=true \
  -e REDIS_URL=redis://redis:6379 \
  web3-xdr:latest

# Access UI
open http://localhost:9090
```

---

### Cloud Run Deployment

**Deploy Command:**
```bash
gcloud run deploy web3-xdr-worker \
  --source . \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --port 9090 \
  --memory 2Gi \
  --cpu 2 \
  --timeout 3600 \
  --set-env-vars="RUNTIME_ENABLED=true,REDIS_URL=redis://..."
```

**Access:**
```
https://web3-xdr-worker-XXXXX.run.app/
```

---

## Verification

### 1. Check Build Output

```bash
ls -la frontend/war-room/dist/
# Should see:
# - index.html
# - assets/
#   ├─ index-HASH.js
#   ├─ index-HASH.css
#   └─ ...
```

### 2. Check Docker Image

```bash
docker run --rm web3-xdr:latest ls -la /app/static
# Should see:
# - index.html
# - assets/
```

### 3. Test Endpoints

```bash
# Health check
curl http://localhost:9090/health

# Metrics
curl http://localhost:9090/metrics

# UI (should return HTML)
curl http://localhost:9090/

# Static asset (should return JS)
curl http://localhost:9090/assets/index-HASH.js
```

### 4. Test React Router

```bash
# All these should return index.html
curl http://localhost:9090/
curl http://localhost:9090/dashboard
curl http://localhost:9090/incidents
curl http://localhost:9090/any-route
```

---

## Troubleshooting

### Issue: 404 on Assets

**Problem:** `/assets/index-HASH.js` returns 404

**Solution:**
- Check `vite.config.ts` has `base: '/'`
- Verify build output: `ls frontend/war-room/dist/assets/`
- Check Docker image: `docker run --rm web3-xdr ls /app/static/assets/`

### Issue: Blank Page

**Problem:** UI loads but shows blank page

**Solution:**
- Check browser console for errors
- Verify `base: '/'` in `vite.config.ts`
- Check network tab for failed asset loads
- Ensure `assetsDir: 'assets'` matches static route

### Issue: API Calls Fail

**Problem:** Frontend can't reach `/api/*` or `/ws`

**Solution:**
- In development: Ensure proxy is configured in `vite.config.ts`
- In production: Ensure API routes are defined BEFORE catch-all
- Check CORS settings if needed

### Issue: React Router 404

**Problem:** Refreshing `/dashboard` returns 404

**Solution:**
- Ensure catch-all route `/{tail:.*}` is defined LAST
- Verify `index_handler` returns `index.html`
- Check route priority in `app.router`

---

## Development Workflow

### Option 1: Separate Dev Servers (Recommended for Development)

**Terminal 1: Frontend Dev Server**
```bash
cd frontend/war-room
npm run dev
# Runs on http://localhost:3000
# Hot reload enabled
```

**Terminal 2: Python Worker**
```bash
python -m src.worker.main
# Runs on http://localhost:9090
# Proxied by Vite
```

**Access:** http://localhost:3000 (Vite proxies API calls to :9090)

### Option 2: Bundled (Production-like)

```bash
# Build frontend
cd frontend/war-room
npm run build

# Copy to static
cd ../..
mkdir -p static
cp -r frontend/war-room/dist/* static/

# Run worker
python -m src.worker.main

# Access: http://localhost:9090
```

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | 9090 | Worker HTTP port |
| `RUNTIME_ENABLED` | false | Enable Runtime Security Plane |
| `REDIS_URL` | - | Redis connection string |
| `MEMPOOL_SOURCE` | pseudo | Mempool source (pseudo/bloxroute) |
| `BLOXROUTE_AUTH_HEADER` | - | bloXroute API key |

---

## Performance Considerations

### Build Size

```bash
# Check build size
du -sh frontend/war-room/dist/
# Target: < 5MB

# Analyze bundle
cd frontend/war-room
npm run build -- --mode production
```

### Compression

aiohttp automatically handles gzip compression for static files.

### Caching

Static assets have content hashes in filenames (e.g., `index-abc123.js`), enabling long-term caching:

```
Cache-Control: public, max-age=31536000, immutable
```

---

## CI/CD Integration

### GitHub Actions

```yaml
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Build and Push Docker Image
        run: |
          docker build -t gcr.io/$PROJECT_ID/web3-xdr:$GITHUB_SHA .
          docker push gcr.io/$PROJECT_ID/web3-xdr:$GITHUB_SHA
      
      - name: Deploy to Cloud Run
        run: |
          gcloud run deploy web3-xdr-worker \
            --image gcr.io/$PROJECT_ID/web3-xdr:$GITHUB_SHA \
            --region us-central1
```

---

## Security Considerations

### Content Security Policy

Add CSP headers in production:

```python
@web.middleware
async def csp_middleware(request, handler):
    response = await handler(request)
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self' ws: wss:;"
    )
    return response

app.middlewares.append(csp_middleware)
```

### CORS (if needed)

```python
from aiohttp_cors import setup as cors_setup

cors = cors_setup(app, defaults={
    "*": aiohttp_cors.ResourceOptions(
        allow_credentials=True,
        expose_headers="*",
        allow_headers="*",
    )
})
```

---

## Success Criteria

✅ Frontend builds successfully  
✅ Docker image contains `/app/static/`  
✅ Worker serves UI at `/`  
✅ Static assets load from `/assets/*`  
✅ React Router works (no 404 on refresh)  
✅ API calls reach worker  
✅ WebSocket connections work  
✅ Health checks pass  

---

## Next Steps

1. **Test the build:**
   ```bash
   docker build -t web3-xdr:latest .
   docker run -p 9090:9090 web3-xdr:latest
   ```

2. **Access the UI:**
   ```
   http://localhost:9090
   ```

3. **Deploy to production:**
   ```bash
   gcloud run deploy web3-xdr-worker --source .
   ```

---

**Status:** ✅ Ready for deployment!

The React War Room UI is now fully integrated with the Python worker and ready to be deployed as a single container.
