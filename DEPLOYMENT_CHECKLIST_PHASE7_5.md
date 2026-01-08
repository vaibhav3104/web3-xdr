# Phase 7.5 Deployment Checklist - bloXroute Integration

## Pre-Deployment Verification

### ✅ Step 1: Local Filter Test

**CRITICAL**: Test the filter logic locally before deploying.

```bash
# 1. Add test address to chains.yaml (temporarily)
# Edit config/chains.yaml:
#   critical_contracts:
#     - "0xYOUR_WALLET_ADDRESS"  # Your MetaMask address

# 2. Run verification test
export BLOXROUTE_AUTH_HEADER="N2Jl..."
python scripts/test_bloxroute_filter.py
```

**Expected Output:**
```
✅ Filter string format is correct
✅ Source started successfully
✅ Source is running
✅ Transaction received:
   Hash: 0x...
   To: 0xYOUR_WALLET_ADDRESS
```

**If you see transactions immediately after sending from MetaMask**, the filter works! ✅

### ✅ Step 2: Verify Filter Syntax

The filter should look like:
```
{to} IN ['0xdac17f958d2ee523a2206206994597c13d831ec7', '0xyour_wallet_address']
```

**Check:**
- ✅ Single quotes around addresses
- ✅ Comma-separated list
- ✅ Lowercase addresses (normalized)
- ✅ No extra spaces

## Deployment Steps

### Step 1: Create bloXroute Secret

```bash
# Option A: Use setup script
chmod +x scripts/setup_bloxroute_secret.sh
./scripts/setup_bloxroute_secret.sh

# Option B: Manual
echo -n "N2JlMjk0OTgtMzFkMC00NDhlLWJlMGMtMWIxYjFiY2ExZTI4OmY0NDY5ODJmZmY5NmY2MjE5ZGJlMzBiODgxNmNlNzMy" | \
    gcloud secrets create web3-xdr-bloxroute-auth-header --data-file=-

# Grant access to Cloud Run service account
SERVICE_ACCOUNT=$(gcloud projects describe web3-xdr --format="value(projectNumber)")-compute@developer.gserviceaccount.com
gcloud secrets add-iam-policy-binding web3-xdr-bloxroute-auth-header \
    --member="serviceAccount:$SERVICE_ACCOUNT" \
    --role="roles/secretmanager.secretAccessor"
```

### Step 2: Update Cloud Run Environment Variables

**For Staging:**
```bash
gcloud run services update web3-xdr-worker \
    --region=us-central1 \
    --update-env-vars MEMPOOL_SOURCE=bloxroute,RUNTIME_ENABLED=true
```

**For Production:**
```bash
gcloud run services update web3-xdr-production-worker \
    --region=us-central1 \
    --update-env-vars MEMPOOL_SOURCE=bloxroute,RUNTIME_ENABLED=true
```

**Note:** The CI/CD workflow (`deploy.yml`) already includes these env vars, but defaults to `MEMPOOL_SOURCE=pseudo` for safety. Update manually or modify the workflow.

### Step 3: Verify chains.yaml Configuration

Ensure your production `chains.yaml` has monitored addresses:

```yaml
chains:
  - chain_id: "ethereum"
    critical_contracts:
      - "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"  # Wormhole
    bridge_contracts:
      - "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"  # LayerZero
      # ... more contracts
```

### Step 4: Deploy via CI/CD

```bash
git add .
git commit -m "Phase 7.5: bloXroute 0-Block Integration"
git push origin main
```

The CI/CD will:
1. Run tests
2. Build Docker image
3. Deploy to Cloud Run
4. Use secrets from Secret Manager

## Post-Deployment Verification

### 1. Check Worker Logs

```bash
# View worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker" \
    --limit=50 \
    --format=json \
    --project=web3-xdr
```

**Look for:**
- ✅ `bloxroute_source_initialized` - Source created
- ✅ `bloxroute_connected` - WebSocket connected
- ✅ `bloxroute_subscription_confirmed` - Feed subscribed
- ✅ `bloxroute_tx_received` - Transactions being received

### 2. Test Transaction Flow

1. Send a test transaction to a monitored address
2. Check logs for `bloxroute_tx_received` (should appear immediately)
3. Check for `predicted_incident_created` (if simulation detects threat)
4. Verify predicted incident appears in frontend

### 3. Monitor Metrics

```bash
# Check Prometheus metrics
curl https://web3-xdr-production-api-ipje7qz66q-uc.a.run.app/metrics | grep runtime
```

**Look for:**
- `sentinel3_runtime_simulations_total` - Should increment
- `sentinel3_runtime_risk_router_decisions_total` - Router decisions
- `sentinel3_predicted_incidents_total` - Predicted incidents

## Troubleshooting

### Issue: "bloxroute_no_monitored_addresses"

**Solution:**
- Add `critical_contracts` or `bridge_contracts` to `chains.yaml`
- Restart worker: `gcloud run services update web3-xdr-production-worker --region=us-central1`

### Issue: "bloxroute_connection_failed"

**Check:**
1. `BLOXROUTE_AUTH_HEADER` secret exists and is correct
2. Service account has `secretmanager.secretAccessor` role
3. Network can reach `wss://api.blxrbdn.com/ws`

### Issue: No transactions received

**Check:**
1. Filter syntax is correct (check logs for filter string)
2. Monitored addresses are correct
3. Transactions are actually targeting those addresses
4. bloXroute account is active and has access to mainnet feed

### Issue: Worker crashes on startup

**Check:**
1. `websockets` library is installed (should be in requirements.txt)
2. `BLOXROUTE_AUTH_HEADER` is set (even if empty, should not crash)
3. Fallback to pseudo source works if bloXroute unavailable

## Rollback Plan

If bloXroute causes issues, rollback to pseudo source:

```bash
gcloud run services update web3-xdr-production-worker \
    --region=us-central1 \
    --update-env-vars MEMPOOL_SOURCE=pseudo
```

The system will automatically fall back to block-based detection.

## Safety Features

1. **Graceful Fallback**: If bloXroute unavailable, falls back to pseudo source
2. **Filter Validation**: Validates filter syntax before subscribing
3. **Queue Limits**: Bounded queue prevents memory issues
4. **Error Handling**: Comprehensive error handling and logging

## Success Criteria

✅ bloXroute connects successfully  
✅ Subscription confirmed  
✅ Transactions received for monitored addresses  
✅ Transactions filtered out for non-monitored addresses  
✅ Predicted incidents created from mempool transactions  
✅ No worker crashes or memory issues  

## Next Steps After Deployment

1. Monitor logs for 24 hours
2. Verify predicted incidents are being created
3. Check simulation performance
4. Adjust budgets if needed (`RUNTIME_PER_CHAIN_SIM_BUDGET`)
5. Remove test addresses from `chains.yaml`

