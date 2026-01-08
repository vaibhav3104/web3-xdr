# Phase 7.5: bloXroute Integration - Quick Start

## 🚀 Pre-Deployment Verification (REQUIRED)

**CRITICAL**: Test the filter logic locally before deploying!

### Option 1: Honey Pot Test (Recommended)

1. **Add your wallet to chains.yaml**:
```yaml
# config/chains.yaml
chains:
  - chain_id: "ethereum"
    critical_contracts:
      - "0xYOUR_WALLET_ADDRESS"  # Your MetaMask address
```

2. **Run verification test**:
```bash
export BLOXROUTE_AUTH_HEADER="N2JlMjk0OTgtMzFkMC00NDhlLWJlMGMtMWIxYjFiY2ExZTI4OmY0NDY5ODJmZmY5NmY2MjE5ZGJlMzBiODgxNmNlNzMy"
python scripts/test_bloxroute_filter.py
```

3. **Send test transaction**:
   - Open MetaMask
   - Send 0 ETH to yourself
   - **Watch for**: `bloxroute_tx_received` should appear **immediately** (before confirmation)

4. **If you see transactions immediately** → Filter works! ✅

### Option 2: High-Traffic Contract Test

The test script already includes USDT contract (high traffic). Just run:

```bash
export BLOXROUTE_AUTH_HEADER="N2Jl..."
python scripts/test_bloxroute_filter.py
```

You should see transactions within seconds.

## 📋 Deployment Checklist

### Step 1: Create Secret

```bash
# Use setup script
./scripts/setup_bloxroute_secret.sh

# Or manual:
echo -n "N2Jl..." | \
    gcloud secrets create web3-xdr-bloxroute-auth-header --data-file=-
```

### Step 2: Grant Access

```bash
SERVICE_ACCOUNT=$(gcloud projects describe web3-xdr --format="value(projectNumber)")-compute@developer.gserviceaccount.com
gcloud secrets add-iam-policy-binding web3-xdr-bloxroute-auth-header \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"
```

### Step 3: Update Cloud Run (Optional - CI/CD handles this)

```bash
# For production
gcloud run services update web3-xdr-production-worker \
    --region=us-central1 \
    --update-env-vars MEMPOOL_SOURCE=bloxroute,RUNTIME_ENABLED=true
```

**Note:** CI/CD workflow already configured. Just push to main branch.

### Step 4: Deploy

```bash
git add .
git commit -m "Phase 7.5: bloXroute 0-Block Integration"
git push origin main
```

## ✅ Post-Deployment Verification

### Check Logs

```bash
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker AND textPayload=~'bloxroute'" \
    --limit=20 \
    --project=web3-xdr
```

**Look for:**
- ✅ `bloxroute_connected`
- ✅ `bloxroute_subscription_confirmed`
- ✅ `bloxroute_tx_received`

### Test Transaction Flow

1. Send transaction to monitored address
2. Check logs for `bloxroute_tx_received` (immediate)
3. Check for `predicted_incident_created` (if threat detected)
4. Verify in frontend (purple "PREDICTED" badge)

## 🛑 Rollback (If Needed)

```bash
gcloud run services update web3-xdr-production-worker \
    --region=us-central1 \
    --update-env-vars MEMPOOL_SOURCE=pseudo
```

System automatically falls back to block-based detection.

## 📚 Documentation

- **Full Guide**: `DEPLOYMENT_CHECKLIST_PHASE7_5.md`
- **Verification**: `VERIFICATION_GUIDE.md`
- **Setup**: `BLOXROUTE_SETUP.md`

## 🎯 Success Criteria

✅ Filter test passes locally  
✅ bloXroute connects in production  
✅ Transactions received for monitored addresses  
✅ Predicted incidents created from mempool  
✅ No worker crashes  

---

**Remember**: Always test the filter locally before deploying! 🚀

