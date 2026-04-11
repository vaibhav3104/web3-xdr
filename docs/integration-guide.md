# Sentinel3 Partner Integration Guide

## Quick Start

### 1. Get an API Key

Contact the Sentinel3 team or use the customer portal to create an API key.
Your key will look like `s3_cust_abc123...` (customer keys) or `pk_live_...` (partner keys).

### 2. Authenticate

Pass your key via the `X-API-Key` header:

```bash
curl -H "X-API-Key: YOUR_KEY" https://api.sentinel3.io/api/v1/health
```

Or as a query parameter:

```bash
curl "https://api.sentinel3.io/api/v1/health?api_key=YOUR_KEY"
```

### 3. Screen a Wallet

```bash
curl -H "X-API-Key: YOUR_KEY" \
  "https://api.sentinel3.io/api/v1/wallet/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045/risk?chain_id=ethereum"
```

Response:

```json
{
  "address": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "chain_id": "ethereum",
  "risk_score": 0.12,
  "risk_level": "low",
  "risk_factors": [],
  "labels": ["known_entity"],
  "transaction_count": 1523,
  "total_volume_usd": 4523100.50,
  "connected_to_mixer": false,
  "connected_to_exchange": false,
  "is_contract": false,
  "explorer_url": "https://etherscan.io/address/0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
}
```

---

## Endpoints

### Wallet Risk Screening

`GET /api/v1/wallet/{address}/risk`

| Param | Type | Default | Description |
|-------|------|---------|-------------|
| address | path | required | Wallet address (0x...) |
| chain_id | query | ethereum | Chain to check |

**Supported chains:** ethereum, polygon, arbitrum, optimism, base, avalanche, bsc

### Contract Threat Analysis

`GET /api/v1/contract/{address}/threat`

Returns threat classification, vulnerability indicators, and deployer risk score.

### Transaction Analysis

`GET /api/v1/transaction/{tx_hash}/analysis`

Returns transaction type, participant risk scores, and alerts.

### Batch Screening

`POST /api/v1/wallets/batch-risk`

Screen up to 100 addresses in a single request.

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '["0xabc...", "0xdef..."]' \
  "https://api.sentinel3.io/api/v1/wallets/batch-risk?chain_id=ethereum"
```

### Usage & Rate Limits

`GET /api/v1/usage`

Check your current request count and limit.

| Tier | Rate Limit | Features |
|------|-----------|----------|
| Free | 100/min | Read-only access |
| Pro | 1,000/min | Read + write + webhooks |
| Enterprise | Custom | Dedicated support |

---

## Webhooks

### Register a Webhook

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{
    "url": "https://your-app.com/sentinel3-webhook",
    "events": ["threat_detected", "incident_created"],
    "secret": "your_hmac_secret"
  }' \
  "https://api.sentinel3.io/api/v1/webhooks/register"
```

### Event Types

| Event | Description |
|-------|-------------|
| `threat_detected` | New threat detected by ML or rules |
| `incident_created` | New security incident created |
| `liquidation_alert` | Large liquidation detected |
| `cross_chain_violation` | Cross-chain bridge invariant violated |

### Verifying Webhook Signatures

Webhooks are signed with HMAC-SHA256 using your secret. Verify the `X-Sentinel3-Signature` header:

```python
import hmac, hashlib

def verify_webhook(payload_bytes, signature, secret):
    expected = hmac.new(
        secret.encode(),
        payload_bytes,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)
```

---

## Integration Examples

### Fireblocks Transaction Screening

Use the `/api/v1/integrations/fireblocks/screen` endpoint:

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '["0xsuspicious_address_1", "0xsuspicious_address_2"]' \
  "https://api.sentinel3.io/api/v1/integrations/fireblocks/screen"
```

Response (Fireblocks-compatible format):

```json
{
  "screeningResults": [
    {
      "address": "0xsuspicious_address_1",
      "risk": "HIGH",
      "score": 0.72,
      "alerts": ["mixer_interaction", "known_exploit_address"]
    }
  ]
}
```

### Safe Transaction Guard

Use the `/api/v1/integrations/safe/check` endpoint before executing Safe transactions:

```bash
curl -X POST -H "X-API-Key: YOUR_KEY" -H "Content-Type: application/json" \
  -d '{
    "safe_address": "0xYourSafe...",
    "to_address": "0xRecipient...",
    "value": "1000000000000000000",
    "data": "0x"
  }' \
  "https://api.sentinel3.io/api/v1/integrations/safe/check"
```

Response:

```json
{
  "safe_address": "0xYourSafe...",
  "to_address": "0xRecipient...",
  "risk_score": 0.15,
  "risk_level": "low",
  "recommendation": "ALLOW",
  "alerts": []
}
```

### Python SDK Example

```python
import httpx

class Sentinel3Client:
    def __init__(self, api_key: str, base_url: str = "https://api.sentinel3.io"):
        self.client = httpx.Client(
            base_url=base_url,
            headers={"X-API-Key": api_key},
            timeout=10.0,
        )

    def screen_wallet(self, address: str, chain: str = "ethereum") -> dict:
        resp = self.client.get(f"/api/v1/wallet/{address}/risk", params={"chain_id": chain})
        resp.raise_for_status()
        return resp.json()

    def screen_contract(self, address: str, chain: str = "ethereum") -> dict:
        resp = self.client.get(f"/api/v1/contract/{address}/threat", params={"chain_id": chain})
        resp.raise_for_status()
        return resp.json()

    def batch_screen(self, addresses: list, chain: str = "ethereum") -> dict:
        resp = self.client.post(f"/api/v1/wallets/batch-risk", json=addresses, params={"chain_id": chain})
        resp.raise_for_status()
        return resp.json()

    def get_usage(self) -> dict:
        resp = self.client.get("/api/v1/usage")
        resp.raise_for_status()
        return resp.json()


# Usage
client = Sentinel3Client("pk_live_your_key")
risk = client.screen_wallet("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
print(f"Risk: {risk['risk_score']} ({risk['risk_level']})")
```

---

## Error Handling

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Bad request (invalid parameters) |
| 401 | Invalid or missing API key |
| 403 | Insufficient permissions |
| 404 | Resource not found |
| 429 | Rate limit exceeded (check `Retry-After` header) |
| 500 | Server error |

---

## Interactive Docs

- **Swagger UI:** `https://api.sentinel3.io/api/docs`
- **ReDoc:** `https://api.sentinel3.io/api/redoc`
- **OpenAPI JSON:** `https://api.sentinel3.io/openapi.json`
