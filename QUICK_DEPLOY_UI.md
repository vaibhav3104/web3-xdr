# Quick Deploy - Bundled UI

## 🚀 One-Command Deploy

```bash
# Build and run
docker build -t web3-xdr:latest . && \
docker run -p 9090:9090 \
  -e RUNTIME_ENABLED=true \
  web3-xdr:latest

# Access: http://localhost:9090
```

---

## 📋 What Changed

| File | Change |
|------|--------|
| `Dockerfile` | Multi-stage build (Node → Python) |
| `src/worker/main.py` | Added static file serving + SPA catch-all |
| `frontend/war-room/vite.config.ts` | Set `base: '/'` |

---

## 🔍 Verify

```bash
# 1. Check build output
ls frontend/war-room/dist/

# 2. Check Docker image
docker run --rm web3-xdr:latest ls /app/static

# 3. Test endpoints
curl http://localhost:9090/health    # Health check
curl http://localhost:9090/           # UI (HTML)
curl http://localhost:9090/metrics    # Metrics
```

---

## 🎯 Routes

```
Priority Order:
1. /health     → Health check (API)
2. /metrics    → Prometheus metrics (API)
3. /assets/*   → Static files (JS/CSS)
4. /*          → index.html (React Router catch-all)
```

---

## 🐛 Troubleshoot

**Blank page?**
- Check: `base: '/'` in `vite.config.ts`
- Check: Browser console for 404s

**Assets 404?**
- Verify: `ls /app/static/assets/` in container
- Check: `app.router.add_static('/assets', ...)` in worker

**React Router 404?**
- Ensure: Catch-all route is LAST
- Verify: `index_handler` returns `index.html`

---

## 📦 Build Sizes

```bash
# Check frontend build
du -sh frontend/war-room/dist/
# Target: < 5MB

# Check Docker image
docker images web3-xdr:latest
# Target: < 500MB
```

---

## ☁️ Deploy to Cloud Run

```bash
gcloud run deploy web3-xdr-worker \
  --source . \
  --region us-central1 \
  --port 9090 \
  --allow-unauthenticated
```

---

## ✅ Success Checklist

- [ ] `npm run build` succeeds
- [ ] Docker build completes
- [ ] Container starts on port 9090
- [ ] `/health` returns 200
- [ ] `/` returns HTML
- [ ] `/assets/index-*.js` returns JS
- [ ] React Router works (refresh any route)
- [ ] WebSocket connects

---

**Ready to deploy!** 🎉
