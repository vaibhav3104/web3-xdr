#!/usr/bin/env python3
"""
Test YAML Rules with Enriched Event Data
=========================================

This script tests if YAML rules will trigger with properly enriched events
that include amount_usd values.
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rules.engine import RuleEngine


def test_yaml_rules():
    """Test YAML rules with sample enriched events."""
    
    print("=" * 60)
    print("  YAML Rule Engine Test")
    print("=" * 60)
    
    # Load rules
    rule_engine = RuleEngine()
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "rules")
    rules_loaded = rule_engine.load_rules_from_directory(rules_dir)
    
    print(f"\n✅ Loaded {rules_loaded} rules")
    print(f"   Stats: {rule_engine.stats()}")
    
    # Test events with different USD values
    test_events = [
        {
            "name": "Small Transfer ($5K)",
            "event": {
                "event_type": "Transfer",
                "chain_id": "ethereum",
                "amount": 1.5,
                "amount_usd": 4800.0,  # ~1.5 ETH at $3200
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
            "expected_matches": 0,
        },
        {
            "name": "Medium Transfer ($150K)",
            "event": {
                "event_type": "Transfer",
                "chain_id": "ethereum",
                "amount": 46.875,
                "amount_usd": 150000.0,  # ~46.875 ETH at $3200
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
            "expected_matches": 0,  # Most rules need $1M+
        },
        {
            "name": "Large Bridge Transfer ($1.5M)",
            "event": {
                "event_type": "Transfer",
                "chain_id": "ethereum",
                "amount": 468.75,
                "amount_usd": 1500000.0,  # $1.5M
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
            "expected_matches": 1,  # Should match large-bridge-transfer-101
        },
        {
            "name": "Whale Transfer ($12M)",
            "event": {
                "event_type": "Transfer",
                "chain_id": "ethereum",
                "amount": 3750.0,
                "amount_usd": 12000000.0,  # $12M
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
            "expected_matches": 1,  # Should match
        },
        {
            "name": "Lock Event ($2M)",
            "event": {
                "event_type": "Lock",
                "chain_id": "polygon",
                "amount": 625.0,
                "amount_usd": 2000000.0,  # $2M
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xbridge...",
            },
            "expected_matches": 1,  # Should match large-bridge-transfer-101
        },
        {
            "name": "Mint Event ($500K)",
            "event": {
                "event_type": "Mint",
                "chain_id": "arbitrum",
                "amount": 156.25,
                "amount_usd": 500000.0,  # $500K
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xbridge...",
            },
            "expected_matches": 0,  # Below $1M threshold
        },
        {
            "name": "Withdrawal Event ($200K)",
            "event": {
                "event_type": "Withdrawal",
                "chain_id": "ethereum",
                "amount": 62.5,
                "amount_usd": 200000.0,  # $200K
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xbridge...",
            },
            "expected_matches": 1,  # Should match suspicious-withdrawal-104 ($100K threshold)
        },
        {
            "name": "String amount_usd ($1.2M)",
            "event": {
                "event_type": "Transfer",
                "chain_id": "ethereum",
                "amount": "375.0",  # String
                "amount_usd": "1200000.0",  # String - should still work
                "from_address": "0x123...",
                "to_address": "0x456...",
                "contract_address": "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
            },
            "expected_matches": 1,  # Should match
        },
    ]
    
    print("\n" + "=" * 60)
    print("  Testing Events")
    print("=" * 60)
    
    total_matches = 0
    for test in test_events:
        matches = rule_engine.evaluate(test["event"])
        total_matches += len(matches)
        
        status = "✅" if len(matches) >= test["expected_matches"] else "❌"
        print(f"\n{status} {test['name']}")
        amount_usd = test['event'].get('amount_usd', 0)
        try:
            amount_usd = float(amount_usd)
        except:
            amount_usd = 0
        print(f"   Amount USD: ${amount_usd:,.2f}")
        print(f"   Matches: {len(matches)}")
        
        if matches:
            for match in matches:
                print(f"   → Rule: {match.rule.name} ({match.rule.severity})")
                print(f"     Confidence: {match.rule.confidence}")
                if match.match_details.get("amount_usd"):
                    print(f"     Matched USD: ${match.match_details['amount_usd']:,.2f}")
    
    print("\n" + "=" * 60)
    print(f"  Summary: {total_matches} total rule matches")
    print("=" * 60)
    
    # Test specific rules
    print("\n" + "=" * 60)
    print("  Rule Details")
    print("=" * 60)
    
    key_rules = [
        "large-bridge-transfer-101",
        "suspicious-withdrawal-104",
        "flash-loan-106",
    ]
    
    for rule_id in key_rules:
        rule = rule_engine.get_rule(rule_id)
        if rule:
            print(f"\n📋 {rule.name}")
            print(f"   ID: {rule.id}")
            print(f"   Severity: {rule.severity}")
            print(f"   Confidence: {rule.confidence}")
            print(f"   Detection: {rule.detection}")
            print(f"   Thresholds: {rule.thresholds}")
        else:
            print(f"\n❌ Rule not found: {rule_id}")
    
    return total_matches > 0


if __name__ == "__main__":
    success = test_yaml_rules()
    sys.exit(0 if success else 1)
