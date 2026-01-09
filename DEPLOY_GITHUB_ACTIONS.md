# 🎯 Quick Deploy: GitHub Actions CI/CD

## ⚡ 3-Minute Setup

### 1️⃣ Create GCP Service Account Key

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr

# Create service account (if not exists)
gcloud iam service-accounts create github-actions \
  --project=web3-xdr \
  --display-name="GitHub Actions CI/CD"

# Grant permissions
for role in run.admin artifactregistry.writer iam.serviceAccountUser secretmanager.secretAccessor; do
  gcloud projects add-iam-policy-binding web3-xdr \
    --member="serviceAccount:github-actions@web3-xdr.iam.gserviceaccount.com" \
    --role="roles/${role}"
done

# Create JSON key
gcloud iam service-accounts keys create github-actions-key.json \
  --iam-account=github-actions@web3-xdr.iam.gserviceaccount.com

# Display key (copy this entire output)
cat github-actions-key.json
```

### 2️⃣ Add GitHub Secret

1. Go to: **https://github.com/vaibhav3104/web3-xdr/settings/secrets/actions**
2. Click **"New repository secret"**
3. Name: `GCP_SA_KEY`
4. Value: Paste the entire JSON from `github-actions-key.json`
5. Click **"Add secret"**

### 3️⃣ Create Artifact Registry (if not exists)

```bash
gcloud artifacts repositories create web3-xdr-repo \
  --repository-format=docker \
  --location=us-central1 \
  --project=web3-xdr
```

---

## 🚀 Deploy Now

### Deploy to Staging

```bash
git checkout develop  # or: git checkout -b develop
git add .
git commit -m "Deploy bundled UI to staging"
git push origin develop
```

**Monitor**: https://github.com/vaibhav3104/web3-xdr/actions

### Deploy to Production

```bash
git checkout main
git merge develop
git push origin main
```

---

## 🔍 What Gets Deployed

### Staging (develop branch)
- **API**: `web3-xdr-api`
- **Worker + UI**: `web3-xdr-worker`
- **Environment**: Staging

### Production (main branch)
- **API**: `web3-xdr-production-api`
- **Worker + UI**: `web3-xdr-production-worker`
- **Environment**: Production

---

## 📦 What's Inside the Docker Image

```
Multi-stage Build:
┌─────────────────────────────────────┐
│ Stage 1: Node.js (Frontend Builder) │
│ ✅ npm install                       │
│ ✅ npm run build                     │
│ ✅ Produces dist/ folder             │
└─────────────────────────────────────┘
              ⬇️
┌─────────────────────────────────────┐
│ Stage 2: Python (Final Image)       │
│ ✅ Copies dist/ → /app/static        │
│ ✅ Installs Python deps              │
│ ✅ Bundles everything                │
└─────────────────────────────────────┘
```

---

## ✅ Verify Deployment

### Check Status

```bash
# Get staging URLs
gcloud run services describe web3-xdr-worker \
  --region us-central1 \
  --format='value(status.url)'

# Get production URLs
gcloud run services describe web3-xdr-production-worker \
  --region us-central1 \
  --format='value(status.url)'
```

### Test Endpoints

```bash
# Replace with your actual URL
WORKER_URL="https://web3-xdr-worker-xyz.run.app"

# Health check
curl $WORKER_URL/health

# Metrics
curl $WORKER_URL/metrics

# UI (open in browser)
open $WORKER_URL/
```

---

## 🐛 Quick Fixes

### ❌ "Unauthorized" During Deployment

**Fix**: Re-create service account key and update GitHub secret

```bash
gcloud iam service-accounts keys create github-actions-key-new.json \
  --iam-account=github-actions@web3-xdr.iam.gserviceaccount.com
cat github-actions-key-new.json
# Copy and update GitHub secret
```

### ❌ Frontend Build Fails

**Fix**: Regenerate `package-lock.json`

```bash
cd frontend/war-room
rm -rf node_modules package-lock.json
npm install
git add package-lock.json
git commit -m "Fix package-lock.json"
git push
```

### ❌ Worker Not Accessible

**Fix**: Make worker public

```bash
gcloud run services update web3-xdr-worker \
  --region us-central1 \
  --allow-unauthenticated
```

---

## 📊 GitHub Actions Workflow

**File**: `.github/workflows/deploy.yml`

**Triggers**:
- ✅ Push to `develop` → Staging
- ✅ Push to `main` → Production
- ✅ Pull requests to `main` → Test only

**Jobs**:
1. **Test**: Python tests + Frontend build verification
2. **Deploy-Staging**: Multi-stage Docker build + Deploy to staging
3. **Deploy-Production**: Multi-stage Docker build + Deploy to production

---

## 🎉 Success Checklist

- [ ] GitHub secret `GCP_SA_KEY` configured
- [ ] Artifact Registry `web3-xdr-repo` created
- [ ] GCP secrets exist (infura-api-key, jwt-secret, etc.)
- [ ] Service account has required permissions
- [ ] Pushed code to `develop` or `main` branch
- [ ] GitHub Actions workflow completed successfully
- [ ] Accessed UI at worker URL
- [ ] Health check returns 200 OK

---

## 📚 Full Documentation

For detailed setup instructions, see: **`GITHUB_ACTIONS_SETUP.md`**

---

**Status**: ✅ **READY TO DEPLOY**

Run `git push origin develop` to start your first deployment! 🚀
