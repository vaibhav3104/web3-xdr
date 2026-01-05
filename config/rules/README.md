# Sentinel3 Alert Rules

Alert rules are defined in YAML format, similar to Sigma rules for traditional SIEM.

## Rule Structure

```yaml
id: unique-rule-id
name: Human Readable Name
description: What this rule detects
author: Your Name
created: 2024-01-01
severity: critical|high|medium|low
confidence: 0.0-1.0
enabled: true|false

# What to detect
detection:
  event_type: Transfer|Mint|Lock|Withdrawal|etc
  chain: ethereum|polygon|solana|any
  conditions:
    - field: amount_usd
      operator: gt
      value: 1000000

# How often to check
schedule:
  type: realtime|interval
  interval: 60  # seconds (for interval type)

# What to do when triggered
actions:
  - type: alert
    channels: [telegram, slack]
  - type: webhook
    url: https://your-api.com/alert
```

## Example Rules

See the `.yaml` files in this directory for examples.

