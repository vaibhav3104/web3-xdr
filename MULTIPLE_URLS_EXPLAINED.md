# 🔗 Multiple URLs Explained - Service Architecture

## 📋 Summary

You have **4 Cloud Run services** deployed, but only **2 are currently active/needed** for production.

---

## 🗂️ All Services

### **Production Services (Current - Keep These)**

#### 1. API Service
```
Service: web3-xdr-production-api
URL:     https://web3-xdr-production-api-1003459948096.us-central1.run.app
Port:    8080
Purpose: REST API endpoints for the application
Status:  ✅ ACTIVE
```

#### 2. Worker Service (with War Room UI)
```
Service: web3-xdr-production-worker
URL:     https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
Port:    9090
Purpose: Backend worker + React War Room Dashboard
Status:  ✅ ACTIVE (Latest deployment - Jan 9, 2026)
```

**This is your main UI!** ✨

---

### **Legacy Services (Old - Can Delete)**

#### 3. Original Service
```
Service: web3-xdr
URL:     https://web3-xdr-1003459948096.us-central1.run.app
Purpose: Original/first deployment
Status:  🔄 OLD (can be deleted)
```

#### 4. Legacy Production
```
Service: web3-xdr-production
URL:     https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/index.html
Purpose: Previous production deployment with old UI structure
Status:  🔄 OLD (superseded by web3-xdr-production-worker)
```

---

## 🎯 Which URL to Use?

### **✅ Primary URL (Use This)**
```
https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
```

**Features:**
- ✅ Latest React War Room Dashboard
- ✅ Real-time threat feed
- ✅ Cross-chain graph visualization
- ✅ WebSocket integration
- ✅ Optimized Vite build (331KB)
- ✅ All fixes applied (Jan 9, 2026)
- ✅ Multi-stage Docker build
- ✅ Modern UI/UX

### **❌ Legacy URL (Don't Use)**
```
https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/index.html
```

**Issues:**
- ❌ Old deployment
- ❌ Outdated UI structure
- ❌ Missing recent features
- ❌ Not using bundled approach
- ❌ Older build system

---

## 🔍 Why Multiple Services Exist?

### **Historical Context**

Over the course of development, you've had multiple deployments:

1. **Initial Deployment** (`web3-xdr`)
   - First version deployed to Cloud Run
   - Basic functionality

2. **Production V1** (`web3-xdr-production`)
   - Moved to production naming
   - Served HTML from `/frontend/` directory
   - Deployed: January 8, 2026

3. **Split Architecture** (`web3-xdr-production-api` + `web3-xdr-production-worker`)
   - Separated API from Worker
   - Deployed: January 9, 2026 (today)
   - **Current active architecture**

4. **Bundled UI** (`web3-xdr-production-worker`)
   - Added React War Room Dashboard
   - Multi-stage Docker build
   - Bundled frontend with backend
   - **Latest deployment - what we just did!**

---

## 💰 Cost Impact

Having multiple services running costs money:

| Service | Monthly Cost | Status |
|---------|--------------|--------|
| web3-xdr | ~$30-50 | ❌ Unused (wasting money) |
| web3-xdr-production | ~$50-75 | ❌ Unused (wasting money) |
| web3-xdr-production-api | ~$50-75 | ✅ Active (needed) |
| web3-xdr-production-worker | ~$100-150 | ✅ Active (needed) |

**Potential Savings**: ~$80-125/month by deleting old services

---

## 🧹 Cleanup Old Services

### **Option 1: Using the Script**

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
./cleanup-old-services.sh
```

This will:
1. Show you which services will be deleted
2. Ask for confirmation
3. Delete `web3-xdr` and `web3-xdr-production`
4. Keep `web3-xdr-production-api` and `web3-xdr-production-worker`

### **Option 2: Manual Deletion**

```bash
# Delete old services
gcloud run services delete web3-xdr \
  --region us-central1 \
  --project web3-xdr \
  --quiet

gcloud run services delete web3-xdr-production \
  --region us-central1 \
  --project web3-xdr \
  --quiet
```

### **Option 3: Via GCP Console**

1. Go to: https://console.cloud.google.com/run?project=web3-xdr
2. Select `web3-xdr` → Click "Delete"
3. Select `web3-xdr-production` → Click "Delete"
4. Keep `web3-xdr-production-api` and `web3-xdr-production-worker`

---

## 🏗️ Current Architecture (After Cleanup)

```
┌─────────────────────────────────────────────────────────┐
│                     PRODUCTION                          │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌──────────────────────────────────────────────┐     │
│  │  web3-xdr-production-api (Port 8080)         │     │
│  │  ✅ REST API endpoints                        │     │
│  │  ✅ /health, /metrics, etc                    │     │
│  └──────────────────────────────────────────────┘     │
│                                                         │
│  ┌──────────────────────────────────────────────┐     │
│  │  web3-xdr-production-worker (Port 9090)      │     │
│  │  ✅ Backend Worker + Runtime Engine           │     │
│  │  ✅ React War Room Dashboard (Bundled)        │     │
│  │  ✅ WebSocket (/ws)                            │     │
│  │  ✅ Static files (/assets)                     │     │
│  │  ✅ Health & Metrics (/health, /metrics)      │     │
│  └──────────────────────────────────────────────┘     │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Service Comparison

| Feature | Legacy (web3-xdr-production) | Current (web3-xdr-production-worker) |
|---------|------------------------------|--------------------------------------|
| **UI Framework** | Old HTML structure | ✅ React + Vite |
| **Build System** | Basic | ✅ Multi-stage Docker |
| **Bundle Size** | Large/unoptimized | ✅ 331KB (105KB gzipped) |
| **WebSocket** | ❌ No | ✅ Yes (/ws) |
| **Real-time Feed** | ❌ No | ✅ Yes |
| **War Room Dashboard** | ❌ No | ✅ Yes |
| **Cross-chain Graph** | ❌ No | ✅ Yes |
| **Dark Theme** | Basic | ✅ Modern cybersecurity theme |
| **Deployment** | Manual | ✅ Automated (GitHub Actions) |
| **Last Updated** | Jan 8, 2026 | ✅ Jan 9, 2026 |

---

## 🎯 Action Items

### **Immediate Actions**

1. **✅ Bookmark the correct URL:**
   ```
   https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
   ```

2. **🧹 Delete old services** (saves ~$80-125/month):
   ```bash
   cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
   ./cleanup-old-services.sh
   ```

3. **📝 Update documentation** with the correct production URL

4. **🔗 Share the correct URL** with your team/stakeholders

### **Optional Actions**

5. **🌐 Set up custom domain** (e.g., `war-room.yourdomain.com`)
   - Map to `web3-xdr-production-worker`
   - Easier to remember
   - Professional appearance

6. **📊 Set up monitoring** for the correct services only
   - Monitor `web3-xdr-production-api`
   - Monitor `web3-xdr-production-worker`
   - Ignore old services

---

## 🔐 URL Structure Explained

### **Cloud Run URL Format**
```
https://[SERVICE-NAME]-[PROJECT-HASH].[REGION].run.app
```

**Example:**
```
https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
         ↓                          ↓           ↓
    Service Name              Project Hash   Region
```

- **Service Name**: `web3-xdr-production-worker`
- **Project Hash**: `ipje7qz66q` (unique identifier for your project)
- **Region**: `us-central1` (uc = us-central)

---

## 📚 Quick Reference

### **Production URLs (Current)**
```
Main UI:   https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/
API:       https://web3-xdr-production-api-1003459948096.us-central1.run.app
Health:    https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/health
Metrics:   https://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/metrics
WebSocket: wss://web3-xdr-production-worker-ipje7qz66q-uc.a.run.app/ws
```

### **Legacy URLs (To Be Deleted)**
```
❌ https://web3-xdr-1003459948096.us-central1.run.app
❌ https://web3-xdr-production-1003459948096.us-central1.run.app/frontend/index.html
```

---

## ✅ Recommended: Clean Up Now

**Run this to save money and avoid confusion:**

```bash
cd /Users/vaibhav.tiwari/siem-optimizer/web3-xdr
./cleanup-old-services.sh
```

**After cleanup, you'll have:**
- ✅ 2 services (API + Worker with UI)
- ✅ Lower monthly costs
- ✅ Simpler architecture
- ✅ No confusion about which URL to use

---

**Summary**: Use `web3-xdr-production-worker` URL as your main dashboard, and delete the old services to save money! 🎉
