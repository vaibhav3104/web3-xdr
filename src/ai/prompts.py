"""
AI Prompts for Incident Analysis.

Contains expert-crafted prompts for Web3 security incident analysis.
"""

# Known attack patterns for context
ATTACK_PATTERNS = {
    "unbacked_mint": {
        "name": "Unbacked Mint Attack",
        "description": "Tokens minted on destination chain without corresponding lock on source chain",
        "real_examples": ["Wormhole ($320M, Feb 2022)", "Ronin Bridge ($625M, Mar 2022)"],
        "indicators": [
            "Mint event without matching Lock event",
            "Signature verification bypass",
            "Guardian/validator compromise"
        ],
        "severity": "critical",
        "immediate_actions": [
            "Pause bridge contracts immediately",
            "Alert all validators/guardians",
            "Freeze affected tokens if possible"
        ]
    },
    "flash_loan_exploit": {
        "name": "Flash Loan Exploit",
        "description": "Using uncollateralized loans to manipulate prices or exploit protocol logic",
        "real_examples": ["Euler Finance ($197M, Mar 2023)", "Cream Finance ($130M, Oct 2021)"],
        "indicators": [
            "Large flash loan borrow",
            "Price oracle manipulation",
            "Profit extraction in same block"
        ],
        "severity": "critical",
        "immediate_actions": [
            "Review oracle price feeds",
            "Check for arbitrage opportunities",
            "Analyze transaction trace"
        ]
    },
    "liquidity_drain": {
        "name": "Liquidity Drain",
        "description": "Rapid withdrawal of liquidity from pools exceeding normal patterns",
        "real_examples": ["Nomad Bridge ($190M, Aug 2022)", "BNB Bridge ($570M, Oct 2022)"],
        "indicators": [
            "TVL dropping rapidly (>10% per hour)",
            "Multiple large withdrawals",
            "Unusual withdrawal patterns"
        ],
        "severity": "high",
        "immediate_actions": [
            "Monitor TVL in real-time",
            "Check withdrawal rate limits",
            "Alert liquidity providers"
        ]
    },
    "money_laundering": {
        "name": "Cross-chain Money Laundering",
        "description": "Moving funds across multiple bridges to obscure origin",
        "real_examples": ["Lazarus Group attacks", "Tornado Cash usage post-hack"],
        "indicators": [
            "Multiple bridge hops in short time",
            "Funds from known exploit addresses",
            "Mixer service usage"
        ],
        "severity": "critical",
        "immediate_actions": [
            "Track fund movement across chains",
            "Alert exchanges for potential deposits",
            "Coordinate with chain analytics firms"
        ]
    },
    "message_forgery": {
        "name": "Cross-chain Message Forgery",
        "description": "Forging cross-chain messages to execute unauthorized actions",
        "real_examples": ["LayerZero theoretical attack vectors"],
        "indicators": [
            "Invalid oracle signatures",
            "Relayer verification failure",
            "Nonce manipulation"
        ],
        "severity": "high",
        "immediate_actions": [
            "Verify message authenticity",
            "Check oracle/relayer status",
            "Review security assumptions"
        ]
    },
    "velocity": {
        "name": "Transaction Velocity Anomaly",
        "description": "Unusual spike in transaction frequency indicating potential attack preparation",
        "real_examples": ["Pre-attack reconnaissance patterns"],
        "indicators": [
            "Transaction rate exceeds normal by 5x+",
            "Unusual patterns from new addresses",
            "Contract interaction spikes"
        ],
        "severity": "medium",
        "immediate_actions": [
            "Monitor affected addresses",
            "Review contract interactions",
            "Prepare incident response"
        ]
    }
}

# Main analysis prompt
INCIDENT_ANALYSIS_PROMPT = """You are an expert Web3 security analyst working for a cross-chain bridge security monitoring system (XDR). 

Analyze the following security incident and provide a clear, actionable explanation.

## INCIDENT DATA
```json
{incident_json}
```

## KNOWN ATTACK PATTERN
{attack_pattern_info}

## YOUR ANALYSIS MUST INCLUDE:

### 1. Executive Summary (2-3 sentences)
What happened, how severe is it, and what's the immediate risk?

### 2. Technical Breakdown
- What specific vulnerability or attack vector was exploited?
- What on-chain evidence supports this conclusion?
- How does this compare to known attacks?

### 3. Impact Assessment
- Estimated financial impact (if applicable)
- Affected chains and protocols
- Potential secondary effects

### 4. Recommended Actions (prioritized)
1. Immediate (next 5 minutes)
2. Short-term (next hour)
3. Medium-term (next 24 hours)

### 5. Root Cause Hypothesis
What likely caused this incident? Is it a known vulnerability pattern?

### 6. Confidence Level
How confident are you in this analysis? What additional data would help?

Be specific, technical, and actionable. Security teams will use this to respond to the incident.
"""

# Quick summary prompt (for dashboard)
QUICK_SUMMARY_PROMPT = """Summarize this Web3 security incident in exactly 2 sentences:

Incident: {incident_title}
Type: {attack_type}
Severity: {severity}
Estimated Loss: ${total_loss_usd:,.0f}
Affected Chains: {affected_chains}

First sentence: What happened and the impact.
Second sentence: The most critical action to take right now.
"""

# Recommendation prompt
RECOMMENDATION_PROMPT = """Based on this {attack_type} incident with {severity} severity and ${total_loss_usd:,.0f} at risk:

Provide exactly 3 specific, actionable recommendations that a security team can execute immediately:

1. [IMMEDIATE - within 5 minutes]
2. [SHORT-TERM - within 1 hour]  
3. [PREVENTIVE - to avoid recurrence]

Be specific with contract addresses, function calls, or monitoring thresholds where applicable.
"""

