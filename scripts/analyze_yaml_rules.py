#!/usr/bin/env python3
"""
Comprehensive YAML Rule Analysis
================================

Analyzes all 130 YAML rules to check if they will work with the current
event data being ingested.
"""

import sys
import os
import yaml
from collections import defaultdict
from typing import Dict, List, Set, Any

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# Event types we're actually ingesting (from API stats)
ACTUAL_EVENT_TYPES = {
    "unknown": 36461,
    "transfer": 10858,
    "Event": 6344,
    "LayerZero:SendToChain": 2449,
    "Stargate:SendCredits": 2384,
    "contract_deploy": 1272,
    "swap": 1155,
    "Wormhole:MessagePublished": 955,
    "mint": 271,
    "Wormhole:TransferRedeemed": 235,
    "Stargate:CreditChainPath": 73,
    "Transfer": 63,
    "burn": 59,
    "message_sent": 34,
    "liquidity_add": 27,
    "Approval": 26,
    "ContractDeploy:Safe": 25,
    "bridge_deposit": 13,
    "Stargate:Swap": 13,
    "liquidity_remove": 10,
    "ContractDeploy:Suspicious": 6,
    "Synapse:TokenDeposit": 5,
    "flash_borrow": 3,
    "ContractDeploy:reentrancy_exploit": 2,
    "flash_repay": 2,
}

# Fields available in events (from database schema)
AVAILABLE_FIELDS = {
    "event_id", "chain_id", "chain", "event_type", "tx_hash",
    "block_number", "block", "block_timestamp", "timestamp",
    "contract_address", "contract", "from_address", "to_address",
    "amount", "amount_usd", "severity", "raw_data", "data",
}

# Fields that need enrichment (price feed)
ENRICHMENT_FIELDS = {
    "amount_usd": "Price feed (DeFiLlama/CoinGecko)",
    "token_symbol": "Token registry lookup",
    "token_price_usd": "Price feed",
    "protocol": "Protocol registry lookup",
    "from_entity": "Entity registry lookup",
    "to_entity": "Entity registry lookup",
}

# Fields that require special computation
COMPUTED_FIELDS = {
    "drain_percent_per_hour": "TVL tracking over time",
    "drain_amount_usd": "TVL tracking over time",
    "block_operation_count": "Block analysis",
    "block_volume_usd": "Block analysis",
    "same_block": "Block analysis",
    "execution_delay": "Governance tracking",
    "required_delay": "Governance tracking",
    "tx_count_per_minute": "Rate tracking",
    "failed_tx_count": "Transaction status tracking",
    "unique_callers": "Caller tracking",
    "tvl_change_percent": "TVL tracking",
    "price_change_percent": "Price tracking",
    "slippage_percent": "DEX analysis",
    "liquidity_change_percent": "Liquidity tracking",
}


def load_all_rules() -> List[Dict]:
    """Load all YAML rules from config/rules/"""
    rules = []
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "rules")
    
    for filename in os.listdir(rules_dir):
        if filename.endswith(".yaml"):
            filepath = os.path.join(rules_dir, filename)
            with open(filepath, 'r') as f:
                data = yaml.safe_load(f)
                if data and 'rules' in data:
                    for rule in data['rules']:
                        rule['_source_file'] = filename
                        rules.append(rule)
    
    return rules


def analyze_rule(rule: Dict) -> Dict[str, Any]:
    """Analyze a single rule for compatibility."""
    analysis = {
        "id": rule.get("id", "unknown"),
        "name": rule.get("name", "unknown"),
        "severity": rule.get("severity", "unknown"),
        "source_file": rule.get("_source_file", "unknown"),
        "enabled": rule.get("enabled", True),
        "issues": [],
        "warnings": [],
        "status": "OK",
    }
    
    detection = rule.get("detection", {})
    thresholds = rule.get("thresholds", {})
    conditions = detection.get("conditions", [])
    
    # Check event type
    expected_types = detection.get("event_type", [])
    if isinstance(expected_types, str):
        expected_types = [expected_types]
    
    if expected_types and expected_types != ["any"]:
        # Check if any expected type matches actual types (case-insensitive)
        actual_lower = {t.lower() for t in ACTUAL_EVENT_TYPES.keys()}
        matched = False
        for et in expected_types:
            if et.lower() in actual_lower or et == "any":
                matched = True
                break
        
        if not matched:
            analysis["issues"].append(f"Event type(s) {expected_types} not in ingested data")
    
    # Check thresholds for enrichment fields
    if "min_amount_usd" in thresholds:
        analysis["warnings"].append("Requires amount_usd (price feed enrichment)")
    
    if "min_amount" in thresholds:
        analysis["warnings"].append("Requires amount field")
    
    # Check conditions for computed fields
    for condition in conditions:
        field = condition.get("field", "")
        if field in COMPUTED_FIELDS:
            analysis["issues"].append(f"Requires computed field '{field}' ({COMPUTED_FIELDS[field]})")
        elif field in ENRICHMENT_FIELDS:
            analysis["warnings"].append(f"Requires enrichment field '{field}' ({ENRICHMENT_FIELDS[field]})")
        elif field and field not in AVAILABLE_FIELDS:
            analysis["issues"].append(f"Unknown field '{field}'")
    
    # Check detection type
    detection_type = detection.get("type", "event")
    if detection_type == "invariant":
        invariant = detection.get("invariant", "")
        analysis["issues"].append(f"Requires invariant engine: {invariant}")
    elif detection_type == "pattern":
        pattern = detection.get("pattern", "")
        analysis["issues"].append(f"Requires pattern matching: {pattern}")
    elif detection_type == "aggregation":
        analysis["issues"].append("Requires aggregation engine")
    
    # Determine status
    if analysis["issues"]:
        analysis["status"] = "BLOCKED"
    elif analysis["warnings"]:
        analysis["status"] = "NEEDS_ENRICHMENT"
    else:
        analysis["status"] = "READY"
    
    return analysis


def main():
    print("=" * 80)
    print("  COMPREHENSIVE YAML RULE ANALYSIS")
    print("=" * 80)
    
    rules = load_all_rules()
    print(f"\n📋 Loaded {len(rules)} rules from config/rules/")
    
    # Analyze all rules
    analyses = [analyze_rule(rule) for rule in rules]
    
    # Categorize by status
    ready = [a for a in analyses if a["status"] == "READY"]
    needs_enrichment = [a for a in analyses if a["status"] == "NEEDS_ENRICHMENT"]
    blocked = [a for a in analyses if a["status"] == "BLOCKED"]
    
    # Summary
    print("\n" + "=" * 80)
    print("  SUMMARY")
    print("=" * 80)
    print(f"\n✅ READY (will work now):           {len(ready)}")
    print(f"⚠️  NEEDS ENRICHMENT (after deploy): {len(needs_enrichment)}")
    print(f"❌ BLOCKED (needs implementation):   {len(blocked)}")
    
    # By severity
    print("\n" + "-" * 40)
    print("By Severity:")
    for severity in ["critical", "high", "medium", "low"]:
        sev_rules = [a for a in analyses if a["severity"] == severity]
        ready_count = len([a for a in sev_rules if a["status"] == "READY"])
        enrich_count = len([a for a in sev_rules if a["status"] == "NEEDS_ENRICHMENT"])
        blocked_count = len([a for a in sev_rules if a["status"] == "BLOCKED"])
        print(f"  {severity.upper():8} - Ready: {ready_count:2}, Enrichment: {enrich_count:2}, Blocked: {blocked_count:2}")
    
    # Ready rules
    print("\n" + "=" * 80)
    print("  ✅ READY RULES (Will Work Now)")
    print("=" * 80)
    for a in ready[:20]:  # Show first 20
        print(f"\n  [{a['severity'].upper():8}] {a['name']}")
        print(f"            ID: {a['id']}")
        print(f"            File: {a['source_file']}")
    if len(ready) > 20:
        print(f"\n  ... and {len(ready) - 20} more")
    
    # Needs enrichment
    print("\n" + "=" * 80)
    print("  ⚠️  NEEDS ENRICHMENT (Will Work After Deploy)")
    print("=" * 80)
    for a in needs_enrichment[:15]:
        print(f"\n  [{a['severity'].upper():8}] {a['name']}")
        print(f"            ID: {a['id']}")
        for w in a['warnings']:
            print(f"            ⚠️  {w}")
    if len(needs_enrichment) > 15:
        print(f"\n  ... and {len(needs_enrichment) - 15} more")
    
    # Blocked rules
    print("\n" + "=" * 80)
    print("  ❌ BLOCKED RULES (Need Implementation)")
    print("=" * 80)
    
    # Group by issue type
    issue_groups = defaultdict(list)
    for a in blocked:
        for issue in a['issues']:
            issue_groups[issue].append(a)
    
    for issue, rules_with_issue in sorted(issue_groups.items(), key=lambda x: -len(x[1])):
        print(f"\n  Issue: {issue}")
        print(f"  Affects {len(rules_with_issue)} rules:")
        for a in rules_with_issue[:5]:
            print(f"    - {a['name']} ({a['severity']})")
        if len(rules_with_issue) > 5:
            print(f"    ... and {len(rules_with_issue) - 5} more")
    
    # Event type mapping issues
    print("\n" + "=" * 80)
    print("  📊 EVENT TYPE ANALYSIS")
    print("=" * 80)
    
    # What event types do rules expect?
    expected_types = set()
    for rule in rules:
        detection = rule.get("detection", {})
        types = detection.get("event_type", [])
        if isinstance(types, str):
            types = [types]
        expected_types.update(types)
    
    actual_types = set(ACTUAL_EVENT_TYPES.keys())
    
    print("\n  Event types rules expect but we DON'T ingest:")
    missing = expected_types - actual_types - {"any"}
    for t in sorted(missing):
        print(f"    ❌ {t}")
    
    print("\n  Event types we ingest but NO rules use:")
    unused = actual_types - expected_types
    for t in sorted(unused)[:10]:
        count = ACTUAL_EVENT_TYPES.get(t, 0)
        print(f"    📊 {t}: {count} events")
    
    # Recommendations
    print("\n" + "=" * 80)
    print("  🔧 RECOMMENDATIONS")
    print("=" * 80)
    
    print("""
    1. EVENT TYPE NORMALIZATION
       The telemetry layer should normalize event types to match rules:
       - "transfer" → "Transfer"
       - "swap" → "Swap"
       - "mint" → "Mint"
       - "burn" → "Burn"
       - "liquidity_add" → "LiquidityAdd"
       - "bridge_deposit" → "Lock" or "BridgeDeposit"
    
    2. PRICE FEED ENRICHMENT (DONE ✅)
       - amount_usd calculation from price feed
       - Token symbol lookup
       - This is already implemented in the new code!
    
    3. INVARIANT ENGINE
       Several rules require invariant checks:
       - TVL_VELOCITY (drain detection)
       - TIMELOCK_RESPECTED (governance)
       - These need the invariant engine to be active
    
    4. PATTERN MATCHING
       Flash loan and MEV detection need:
       - Block-level analysis
       - Transaction sequence tracking
    
    5. AGGREGATION
       Rate-based rules need:
       - Time-windowed counting
       - Transaction velocity tracking
    """)
    
    return len(blocked) == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
