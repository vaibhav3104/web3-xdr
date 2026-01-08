# bloXroute Filter Verification Guide

## Quick Test (Honey Pot Method)

### Step 1: Add Your Wallet to chains.yaml

Temporarily add your MetaMask wallet address as a "critical contract":

```yaml
# config/chains.yaml
chains:
  - chain_id: "ethereum"
    critical_contracts:
      - "0xYOUR_WALLET_ADDRESS"  # <--- Add this temporarily
    bridge_contracts:
      - "0xdAC17F958D2ee523a2206206994597C13D831ec7"  # USDT (high traffic)
```

### Step 2: Run Verification Test

```bash
export BLOXROUTE_AUTH_HEADER="N2JlMjk0OTgtMzFkMC00NDhlLWJlMGMtMWIxYjFiY2ExZTI4OmY0NDY5ODJmZmY5NmY2MjE5ZGJlMzBiODgxNmNlNzMy"
python scripts/test_bloxroute_filter.py
```

### Step 3: Send Test Transaction

1. Open MetaMask
2. Send 0 ETH (or tiny amount) to your wallet address
3. Watch the test script output

**Expected:** You should see `bloxroute_tx_received` **immediately** (before transaction confirms)

### Step 4: Verify Filter

The test script will show:
```
Filter String: {to} IN ['0xyour_wallet_address', '0xdac17f958d2ee523a2206206994597c13d831ec7']
✅ Filter string format is correct
```

## Alternative: Use High-Traffic Contract

If you don't want to use your wallet, use USDT contract (already in test script):

```bash
# USDT contract receives many transactions
# You should see transactions within seconds
python scripts/test_bloxroute_filter.py
```

## What to Look For

### ✅ Success Indicators

1. **Connection**: `bloxroute_connected`
2. **Subscription**: `bloxroute_subscription_confirmed`
3. **Transactions**: `bloxroute_tx_received` (appears immediately after sending)
4. **Filter Working**: Only transactions to monitored addresses are received

### ❌ Failure Indicators

1. **No Connection**: `bloxroute_connection_failed`
   - Check `BLOXROUTE_AUTH_HEADER`
   - Check network connectivity

2. **Subscription Error**: `bloxroute_subscription_error`
   - Check filter syntax in logs
   - Verify addresses are valid

3. **No Transactions**: No `bloxroute_tx_received` after 2 minutes
   - Check if addresses are correct
   - Verify transactions are actually targeting those addresses
   - Check bloXroute account status

## Filter Syntax Validation

The filter must be:
```
{to} IN ['0xaddress1', '0xaddress2', ...]
```

**Common Mistakes:**
- ❌ Double quotes: `"0x..."` (should be single quotes)
- ❌ Missing quotes: `0x...` (addresses must be quoted)
- ❌ Wrong format: `to IN [...]` (must be `{to} IN [...]`)

## Production Verification

After deployment, verify:

```bash
# Check worker logs
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=web3-xdr-production-worker AND textPayload=~'bloxroute'" \
    --limit=20 \
    --project=web3-xdr
```

Look for:
- `bloxroute_connected` ✅
- `bloxroute_subscription_confirmed` ✅
- `bloxroute_tx_received` ✅ (should appear frequently for high-traffic contracts)

## Cleanup

After verification:
1. Remove test wallet address from `chains.yaml`
2. Keep only production critical contracts
3. Redeploy if needed

