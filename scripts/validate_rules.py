#!/usr/bin/env python3
"""
Validate YAML Rules — Offline CI Check
=======================================

Runs without network or database access.  Validates:
1. YAML parse-ability
2. Required fields present (id, name, severity, enabled, detection)
3. Severity values are valid
4. No duplicate rule IDs
5. Confidence in [0, 1]
6. Detection has event_type

Exit code 0 = all rules valid, 1 = errors found.
"""

import sys
import os
import yaml
from pathlib import Path
from collections import Counter

RULES_DIR = Path(__file__).resolve().parent.parent / "config" / "rules"

VALID_SEVERITIES = {"critical", "high", "medium", "low"}
REQUIRED_FIELDS = {"id", "name", "severity", "enabled", "detection"}


def validate_file(filepath: Path) -> list[str]:
    """Validate a single YAML rule file. Returns list of error strings."""
    errors: list[str] = []
    rel = filepath.relative_to(RULES_DIR.parent.parent)

    try:
        with open(filepath) as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        return [f"{rel}: YAML parse error: {e}"]

    if data is None:
        return [f"{rel}: empty file"]

    # Top-level can be a dict with a list value, or a list directly
    rules: list[dict] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list):
                rules.extend(value)
    elif isinstance(data, list):
        rules = data
    else:
        return [f"{rel}: unexpected top-level type {type(data).__name__}"]

    if not rules:
        errors.append(f"{rel}: no rules found")
        return errors

    ids_in_file: list[str] = []

    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"{rel}[{i}]: rule is not a dict")
            continue

        rule_id = rule.get("id", f"<index {i}>")
        prefix = f"{rel} :: {rule_id}"

        # Required fields
        missing = REQUIRED_FIELDS - set(rule.keys())
        if missing:
            errors.append(f"{prefix}: missing required fields: {missing}")

        # Severity
        severity = str(rule.get("severity", "")).lower()
        if severity and severity not in VALID_SEVERITIES:
            errors.append(f"{prefix}: invalid severity '{severity}' (expected {VALID_SEVERITIES})")

        # Confidence
        confidence = rule.get("confidence")
        if confidence is not None:
            try:
                c = float(confidence)
                if not 0.0 <= c <= 1.0:
                    errors.append(f"{prefix}: confidence {c} out of [0, 1]")
            except (TypeError, ValueError):
                errors.append(f"{prefix}: confidence is not numeric: {confidence}")

        # Detection block
        detection = rule.get("detection")
        if detection is not None and not isinstance(detection, dict):
            errors.append(f"{prefix}: detection must be a dict")
        elif isinstance(detection, dict):
            if "event_type" not in detection and "type" not in detection:
                errors.append(f"{prefix}: detection missing event_type or type")

        ids_in_file.append(rule.get("id", ""))

    return errors


def main() -> int:
    if not RULES_DIR.exists():
        print(f"ERROR: rules directory not found: {RULES_DIR}")
        return 1

    yaml_files = sorted(RULES_DIR.glob("*.yaml")) + sorted(RULES_DIR.glob("*.yml"))
    if not yaml_files:
        print(f"ERROR: no YAML files in {RULES_DIR}")
        return 1

    all_errors: list[str] = []
    all_ids: list[str] = []
    total_rules = 0

    for filepath in yaml_files:
        errs = validate_file(filepath)
        all_errors.extend(errs)

        # Collect IDs for duplicate check
        with open(filepath) as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    for r in v:
                        if isinstance(r, dict):
                            all_ids.append(r.get("id", ""))
                            total_rules += 1
        elif isinstance(data, list):
            for r in data:
                if isinstance(r, dict):
                    all_ids.append(r.get("id", ""))
                    total_rules += 1

    # Duplicate ID check
    id_counts = Counter(i for i in all_ids if i)
    for rule_id, count in id_counts.items():
        if count > 1:
            all_errors.append(f"DUPLICATE rule ID '{rule_id}' appears {count} times across files")

    # Report
    print(f"Validated {total_rules} rules across {len(yaml_files)} files")

    if all_errors:
        print(f"\nFOUND {len(all_errors)} ERROR(S):\n")
        for err in all_errors:
            print(f"  ERROR: {err}")
        return 1

    print("All rules valid.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
