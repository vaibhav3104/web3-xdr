# bloXroute Mempool Integration - Quick Setup Guide

## Overview

bloXroute integration enables **"0-block" detection** - detecting threats the moment they hit the mempool, before they're mined.

## Prerequisites

1. **bloXroute Account**: Sign up at https://bloxroute.com/
2. **Authorization Header**: Get from bloXroute dashboard
3. **Foundry Anvil**: Required for simulation (`foundryup`)

## Configuration

### 1. Environment Variables

Add to your `.env` file:

```bash
# Enable Runtime Security Plane
RUNTIME_ENABLED=true

# Select mempool source
MEMPOOL_SOURCE=bloxroute

# bloXroute Authorization Header
BLOXROUTE_AUTH_HEADER=N2JlMjk0OTgtMzFkMC00NDhlLWJlMGMtMWIxYjFiY2ExZTI4OmY0NDY5ODJmZmY5NmY2MjE5ZGJlMzBiODgxNmNlNzMy
```

### 2. Configure Monitored Addresses

Edit `config/chains.yaml` and ensure your chain has:

```yaml
chains:
  - chain_id: "ethereum"
    chain_name: "Ethereum Mainnet"
    rpc_url: "https://eth.llamarpc.com"
    
    # Critical contracts (for bloXroute filtering)
    critical_contracts:
      - "0x3ee18B2214AFF97000D974cf647E7C347E8fa585"  # Wormhole Token Bridge
      - "0x98f3c9e6E3fAce36bAAd05FE09d375Ef1464288B"  # Wormhole Core Bridge
    
    # Bridge contracts (also monitored)
    bridge_contracts:
      - "0x66A71Dcef29A0fFBDBE3c6a460a3B5BC225Cd675"  # LayerZero
      - "0x8731d54E9D02c286767d56ac03e8037C07e01e98"  # Stargate
```

**Note:** The worker will combine `critical_contracts`, `bridge_contracts`, and `defi_contracts` for monitoring.

## Verification

### 1. Check Worker Logs

Look for these log messages:

```
[INFO] bloxroute_source_initialized chain_id=ethereum monitored_addresses_count=10
[INFO] bloxroute_connecting ws_url=wss://api.blxrbdn.com/ws
[INFO] bloxroute_connected chain_id=ethereum
[INFO] bloxroute_subscription_sent filter="{to} IN ['0x...', '0x...']"
[INFO] bloxroute_subscription_confirmed
[DEBUG] bloxroute_tx_received tx_hash=0x... to=0x...
```

### 2. Test Connection

```bash
# Start worker
export RUNTIME_ENABLED=true
export MEMPOOL_SOURCE=bloxroute
export BLOXROUTE_AUTH_HEADER=your_header_here
python -m src.worker.main
```

### 3. Monitor Predicted Incidents

- Check API: `GET /api/runtime/predicted-incidents`
- Check Frontend: Look for purple "PREDICTED" badges

## Troubleshooting

### Issue: "bloxroute_no_monitored_addresses"

**Solution:** Add `critical_contracts` or `bridge_contracts` to `chains.yaml` for the chain.

### Issue: "bloxroute_connection_failed"

**Check:**
1. `BLOXROUTE_AUTH_HEADER` is correct
2. Network can reach `wss://api.blxrbdn.com/ws`
3. bloXroute account is active

### Issue: "bloxroute_subscription_error"

**Check:**
1. Filter syntax is correct (addresses in single quotes)
2. Addresses are valid Ethereum addresses
3. bloXroute API supports the filter format

### Issue: No transactions received

**Check:**
1. Monitored addresses are correct
2. Transactions are actually targeting those addresses
3. WebSocket connection is active (check logs)

## Fallback Behavior

If bloXroute is unavailable or misconfigured, the system automatically falls back to `PseudoIntentBlockSource` (block-based detection). You'll see:

```
[WARNING] bloxroute_enabled_but_no_auth_header Falling back to pseudo block source
```

## Performance

- **Latency**: <1 second (mempool) vs ~12 seconds (block-based)
- **Queue Size**: 1000 transactions (configurable)
- **Auto-Reconnect**: Exponential backoff (5s → 60s)

## Security

- Transactions are filtered server-side by bloXroute
- Additional client-side filtering for safety
- Queue limits prevent memory issues
- Graceful degradation on errors

## Next Steps

1. Monitor logs for `bloxroute_tx_received`
2. Verify predicted incidents are created
3. Check simulation performance
4. Adjust budgets if needed (`RUNTIME_PER_CHAIN_SIM_BUDGET`)

