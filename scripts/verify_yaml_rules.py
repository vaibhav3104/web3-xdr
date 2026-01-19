#!/usr/bin/env python3
"""
Verify YAML Rules Against Real Event Data
==========================================

This script:
1. Fetches actual events from the production API
2. Tests each event against all YAML rules
3. Reports which rules would trigger
"""

import sys
import os
import json
import requests
from collections import defaultdict

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.rules.engine import RuleEngine
from src.telemetry.event_normalizer import normalize_event_type, event_type_matches

API_BASE = "https://sentinel3-1003459948096.us-central1.run.app"


def fetch_events(limit=100):
    """Fetch events from production API."""
    try:
        resp = requests.get(f"{API_BASE}/api/events?limit={limit}", timeout=30)
        resp.raise_for_status()
        data = resp.json()
        return data.get("events", [])
    except Exception as e:
        print(f"❌ Failed to fetch events: {e}")
        return []


def fetch_stats():
    """Fetch stats from production API."""
    try:
        resp = requests.get(f"{API_BASE}/api/stats", timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        print(f"❌ Failed to fetch stats: {e}")
        return {}


def main():
    print("=" * 80)
    print("  YAML RULE VERIFICATION - REAL EVENT DATA")
    print("=" * 80)
    
    # Load rules
    rule_engine = RuleEngine()
    rules_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "rules")
    rules_loaded = rule_engine.load_rules_from_directory(rules_dir)
    
    print(f"\n📋 Loaded {rules_loaded} rules")
    
    # Fetch stats
    print("\n" + "-" * 40)
    print("Fetching production stats...")
    stats = fetch_stats()
    
    events_by_type = stats.get("events_by_type", {})
    print(f"\n📊 Event Types in Production:")
    for event_type, count in sorted(events_by_type.items(), key=lambda x: -x[1])[:15]:
        normalized = normalize_event_type(event_type)
        print(f"   {event_type:40} → {normalized:20} ({count:,} events)")
    
    # Fetch real events
    print("\n" + "-" * 40)
    print("Fetching real events from production...")
    events = fetch_events(limit=200)
    print(f"📥 Fetched {len(events)} events")
    
    if not events:
        print("❌ No events to test")
        return False
    
    # Test each event against rules
    print("\n" + "=" * 80)
    print("  TESTING EVENTS AGAINST RULES")
    print("=" * 80)
    
    rule_matches = defaultdict(list)
    event_matches = defaultdict(list)
    
    for event in events:
        # Convert API event format to rule engine format
        rule_event = {
            "event_id": event.get("event_id"),
            "chain_id": event.get("chain_id") or event.get("chain"),
            "chain": event.get("chain") or event.get("chain_id"),
            "event_type": event.get("event_type"),
            "tx_hash": event.get("tx_hash"),
            "block_number": event.get("block_number") or event.get("block"),
            "contract_address": event.get("contract_address") or event.get("contract"),
            "from_address": event.get("from_address"),
            "to_address": event.get("to_address"),
            "amount": event.get("amount"),
            "amount_usd": event.get("amount_usd"),
            "severity": event.get("severity"),
        }
        
        # Add raw_data fields if available
        raw_data = event.get("raw_data") or event.get("data")
        if isinstance(raw_data, dict):
            rule_event.update(raw_data)
        
        # Evaluate rules
        matches = rule_engine.evaluate(rule_event)
        
        for match in matches:
            rule_matches[match.rule.id].append(event)
            event_matches[event.get("event_id", "unknown")].append(match.rule)
    
    # Summary
    print("\n" + "=" * 80)
    print("  RESULTS SUMMARY")
    print("=" * 80)
    
    total_matches = sum(len(m) for m in rule_matches.values())
    rules_triggered = len(rule_matches)
    events_matched = len(event_matches)
    
    print(f"\n✅ Total rule matches: {total_matches}")
    print(f"✅ Unique rules triggered: {rules_triggered}")
    print(f"✅ Events that matched rules: {events_matched}")
    
    # Rules that triggered
    print("\n" + "-" * 40)
    print("Rules That Triggered (sorted by match count):")
    for rule_id, matched_events in sorted(rule_matches.items(), key=lambda x: -len(x[1]))[:20]:
        rule = rule_engine.get_rule(rule_id)
        if rule:
            print(f"\n  [{rule.severity.upper():8}] {rule.name}")
            print(f"            ID: {rule_id}")
            print(f"            Matches: {len(matched_events)}")
            # Show sample event types
            event_types = set(e.get("event_type") for e in matched_events[:5])
            print(f"            Event types: {', '.join(event_types)}")
    
    # Rules that did NOT trigger
    print("\n" + "-" * 40)
    print("Rules That Did NOT Trigger:")
    
    all_rule_ids = set(r.id for r in rule_engine.rules)
    triggered_ids = set(rule_matches.keys())
    not_triggered = all_rule_ids - triggered_ids
    
    # Group by severity
    by_severity = defaultdict(list)
    for rule_id in not_triggered:
        rule = rule_engine.get_rule(rule_id)
        if rule:
            by_severity[rule.severity].append(rule)
    
    for severity in ["critical", "high", "medium", "low"]:
        rules = by_severity.get(severity, [])
        if rules:
            print(f"\n  {severity.upper()} ({len(rules)} rules not triggered):")
            for rule in rules[:5]:
                detection = rule.detection
                event_types = detection.get("event_type", ["any"])
                thresholds = rule.thresholds
                print(f"    - {rule.name}")
                print(f"      Event types: {event_types}")
                if thresholds:
                    print(f"      Thresholds: {thresholds}")
            if len(rules) > 5:
                print(f"    ... and {len(rules) - 5} more")
    
    # Analysis: Why rules didn't trigger
    print("\n" + "=" * 80)
    print("  ANALYSIS: Why Rules Didn't Trigger")
    print("=" * 80)
    
    # Check event type coverage
    ingested_types = set(events_by_type.keys())
    
    missing_types = defaultdict(list)
    threshold_issues = defaultdict(list)
    condition_issues = defaultdict(list)
    
    for rule_id in not_triggered:
        rule = rule_engine.get_rule(rule_id)
        if not rule:
            continue
        
        detection = rule.detection
        expected_types = detection.get("event_type", [])
        if isinstance(expected_types, str):
            expected_types = [expected_types]
        
        # Check if event type is missing
        if expected_types and expected_types != ["any"]:
            type_found = False
            for et in expected_types:
                for ingested in ingested_types:
                    if event_type_matches(ingested, [et]):
                        type_found = True
                        break
                if type_found:
                    break
            
            if not type_found:
                missing_types[tuple(expected_types)].append(rule)
                continue
        
        # Check threshold requirements
        thresholds = rule.thresholds
        if thresholds:
            if "min_amount_usd" in thresholds:
                # Check if any events have amount_usd
                has_usd = any(e.get("amount_usd") for e in events)
                if not has_usd:
                    threshold_issues["amount_usd not populated"].append(rule)
                    continue
        
        # Check conditions
        conditions = detection.get("conditions", [])
        for cond in conditions:
            field = cond.get("field", "")
            if field and not any(e.get(field) for e in events):
                condition_issues[field].append(rule)
                break
    
    print("\n1️⃣ Missing Event Types:")
    for types, rules in sorted(missing_types.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"   Event type {types} not ingested → {len(rules)} rules blocked")
    
    print("\n2️⃣ Threshold Issues:")
    for issue, rules in threshold_issues.items():
        print(f"   {issue} → {len(rules)} rules blocked")
    
    print("\n3️⃣ Missing Condition Fields:")
    for field, rules in sorted(condition_issues.items(), key=lambda x: -len(x[1]))[:10]:
        print(f"   Field '{field}' not in events → {len(rules)} rules blocked")
    
    # Final status
    print("\n" + "=" * 80)
    print("  FINAL STATUS")
    print("=" * 80)
    
    working_pct = (rules_triggered / rules_loaded) * 100 if rules_loaded > 0 else 0
    
    print(f"""
    📊 Rule Coverage:
       - Total rules: {rules_loaded}
       - Rules triggered: {rules_triggered} ({working_pct:.1f}%)
       - Rules blocked: {len(not_triggered)}
    
    🔧 To Fix:
       1. Deploy price feed changes → amount_usd will be populated
       2. Event type normalization → already implemented
       3. Add protocol-specific event parsing for:
          - FlashLoan events
          - LiquidationCall events
          - Governance events
    """)
    
    return rules_triggered > 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
