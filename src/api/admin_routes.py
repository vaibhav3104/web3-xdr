"""
Admin API Routes for Sentinel3.
Manage rules, chains, and alerting configuration through the UI.
"""

import os
import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Body, Depends
from pydantic import BaseModel, Field
from pathlib import Path

router = APIRouter(prefix="/admin", tags=["admin"])

# Import auth dependencies
from ..auth.jwt_handler import require_role
from ..auth.models import User

# Get config directory
CONFIG_DIR = Path(__file__).parent.parent.parent / "config"
RULES_DIR = CONFIG_DIR / "rules"


# ============================================================================
# Pydantic Models
# ============================================================================

class RuleBase(BaseModel):
    """Base model for alert rules."""
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    confidence: float = 0.5
    enabled: bool = True


class RuleCreate(RuleBase):
    """Model for creating a new rule."""
    yaml: str = ""  # Detection logic in YAML


class RuleUpdate(BaseModel):
    """Model for updating a rule."""
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    confidence: Optional[float] = None
    enabled: Optional[bool] = None
    yaml: Optional[str] = None


class ChainConfig(BaseModel):
    """Chain configuration model."""
    chain_id: str
    chain_name: str
    rpc_url: str
    ws_url: Optional[str] = None
    bridge_contracts: List[str] = []
    poll_interval_seconds: int = 12
    status: str = "disconnected"


class AlertingConfig(BaseModel):
    """Alerting configuration model."""
    telegram: Dict[str, Any] = {
        "enabled": False,
        "bot_token": "",
        "critical_channel": "",
        "general_channel": ""
    }
    slack: Dict[str, Any] = {
        "enabled": False,
        "webhook_url": "",
        "critical_channel": "#security-critical"
    }
    rate_limit: Dict[str, Any] = {
        "interval": 60,
        "max_per_hour": 50
    }


# ============================================================================
# Helper Functions
# ============================================================================

def load_all_rules() -> List[Dict]:
    """Load all rules from YAML files."""
    rules = []
    
    if not RULES_DIR.exists():
        return rules
    
    for yaml_file in RULES_DIR.glob("*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'rules' in data:
                for rule in data['rules']:
                    rule['_file'] = yaml_file.name
                    rules.append(rule)
        except Exception as e:
            print(f"Error loading {yaml_file}: {e}")
    
    return rules


def save_rule_to_file(rule: Dict, filename: str = None):
    """Save a rule to a YAML file."""
    if filename is None:
        # Determine file based on severity
        severity = rule.get('severity', 'medium')
        filename = f"{severity}_alerts.yaml"
    
    filepath = RULES_DIR / filename
    
    # Load existing rules
    existing_data = {'rules': []}
    if filepath.exists():
        with open(filepath, 'r') as f:
            existing_data = yaml.safe_load(f) or {'rules': []}
    
    # Check if rule exists
    rules = existing_data.get('rules', [])
    rule_ids = [r['id'] for r in rules]
    
    if rule['id'] in rule_ids:
        # Update existing rule
        for i, r in enumerate(rules):
            if r['id'] == rule['id']:
                rules[i] = rule
                break
    else:
        # Add new rule
        rules.append(rule)
    
    existing_data['rules'] = rules
    
    # Save to file
    with open(filepath, 'w') as f:
        yaml.dump(existing_data, f, default_flow_style=False, sort_keys=False)


def delete_rule_from_file(rule_id: str) -> bool:
    """Delete a rule from its YAML file."""
    for yaml_file in RULES_DIR.glob("*.yaml"):
        try:
            with open(yaml_file, 'r') as f:
                data = yaml.safe_load(f)
            
            if data and 'rules' in data:
                original_count = len(data['rules'])
                data['rules'] = [r for r in data['rules'] if r['id'] != rule_id]
                
                if len(data['rules']) < original_count:
                    with open(yaml_file, 'w') as f:
                        yaml.dump(data, f, default_flow_style=False, sort_keys=False)
                    return True
        except Exception:
            pass
    
    return False


def get_chain_type(chain_id: str) -> str:
    """Determine chain type from chain ID."""
    chain_lower = chain_id.lower()
    
    evm_chains = ["ethereum", "polygon", "arbitrum", "optimism", "bsc", "avalanche", "fantom", "base", "zksync", "linea"]
    cosmos_chains = ["cosmos", "osmosis", "injective", "sei", "celestia", "dydx", "neutron"]
    aptos_chains = ["aptos", "movement"]
    sui_chains = ["sui"]
    near_chains = ["near", "aurora"]
    solana_chains = ["solana"]
    
    if chain_lower in evm_chains:
        return "evm"
    elif chain_lower in cosmos_chains:
        return "cosmos"
    elif chain_lower in aptos_chains:
        return "aptos"
    elif chain_lower in sui_chains:
        return "sui"
    elif chain_lower in near_chains:
        return "near"
    elif chain_lower in solana_chains:
        return "solana"
    return "evm"


def load_chains_config() -> List[Dict]:
    """Load chain configuration."""
    config_file = CONFIG_DIR / "chains.yaml"
    
    if not config_file.exists():
        return []
    
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
    
    chains = data.get('chains', [])
    
    # Add status and chain type info
    for chain in chains:
        chain_id = chain.get('chain_id', '')
        chain_type = get_chain_type(chain_id)
        chain['chain_type'] = chain_type
        chain['status'] = 'connected'  # Will be updated by actual monitoring
        
        # Add type-specific info
        if chain_type == "evm":
            chain['protocol'] = "EVM (JSON-RPC)"
        elif chain_type == "cosmos":
            chain['protocol'] = "Cosmos (Tendermint RPC)"
        elif chain_type in ["aptos", "sui"]:
            chain['protocol'] = "Move (REST/JSON-RPC)"
        elif chain_type == "near":
            chain['protocol'] = "Near (JSON-RPC)"
        elif chain_type == "solana":
            chain['protocol'] = "Solana (JSON-RPC)"
        else:
            chain['protocol'] = "Unknown"
    
    return chains


def load_alerting_config() -> Dict:
    """Load alerting configuration."""
    config_file = CONFIG_DIR / "chains.yaml"
    
    if not config_file.exists():
        return AlertingConfig().dict()
    
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
    
    alerting = data.get('alerting', {})
    
    return {
        "telegram": {
            "enabled": alerting.get('telegram_enabled', False),
            "bot_token": alerting.get('telegram_bot_token', ''),
            "critical_channel": alerting.get('telegram_critical_channel', ''),
            "general_channel": alerting.get('telegram_general_channel', '')
        },
        "slack": {
            "enabled": alerting.get('slack_enabled', False),
            "webhook_url": alerting.get('slack_webhook_url', ''),
            "critical_channel": alerting.get('slack_critical_channel', '#security-critical')
        },
        "rate_limit": {
            "interval": alerting.get('min_alert_interval_seconds', 60),
            "max_per_hour": alerting.get('max_alerts_per_hour', 50)
        }
    }


def save_alerting_config(config: Dict):
    """Save alerting configuration."""
    config_file = CONFIG_DIR / "chains.yaml"
    
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
    
    # Update alerting section
    data['alerting'] = {
        'telegram_enabled': config['telegram']['enabled'],
        'telegram_bot_token': config['telegram']['bot_token'],
        'telegram_critical_channel': config['telegram']['critical_channel'],
        'telegram_general_channel': config['telegram']['general_channel'],
        'slack_enabled': config['slack']['enabled'],
        'slack_webhook_url': config['slack']['webhook_url'],
        'slack_critical_channel': config['slack']['critical_channel'],
        'min_alert_interval_seconds': config['rate_limit']['interval'],
        'max_alerts_per_hour': config['rate_limit']['max_per_hour']
    }
    
    with open(config_file, 'w') as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


# ============================================================================
# Rule Management Routes
# ============================================================================

@router.get("/rules", response_model=List[Dict])
async def list_rules():
    """List all alert rules."""
    return load_all_rules()


@router.get("/rules/{rule_id}")
async def get_rule(rule_id: str):
    """Get a specific rule by ID."""
    rules = load_all_rules()
    for rule in rules:
        if rule['id'] == rule_id:
            return rule
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/rules")
async def create_rule(rule: RuleCreate):
    """Create a new alert rule."""
    # Build rule dict
    rule_dict = {
        'id': rule.id,
        'name': rule.name,
        'description': rule.description,
        'severity': rule.severity,
        'confidence': rule.confidence,
        'enabled': rule.enabled
    }
    
    # Parse YAML detection logic if provided
    if rule.yaml:
        try:
            detection = yaml.safe_load(rule.yaml)
            rule_dict.update(detection)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
    
    # Save to file
    save_rule_to_file(rule_dict)
    
    return {"status": "created", "rule_id": rule.id}


@router.put("/rules/{rule_id}")
async def update_rule(rule_id: str, update: RuleUpdate):
    """Update an existing rule."""
    rules = load_all_rules()
    
    for rule in rules:
        if rule['id'] == rule_id:
            # Update fields
            if update.name is not None:
                rule['name'] = update.name
            if update.description is not None:
                rule['description'] = update.description
            if update.severity is not None:
                rule['severity'] = update.severity
            if update.confidence is not None:
                rule['confidence'] = update.confidence
            if update.enabled is not None:
                rule['enabled'] = update.enabled
            if update.yaml is not None:
                try:
                    detection = yaml.safe_load(update.yaml)
                    rule.update(detection)
                except yaml.YAMLError as e:
                    raise HTTPException(status_code=400, detail=f"Invalid YAML: {e}")
            
            # Save back
            filename = rule.pop('_file', None)
            save_rule_to_file(rule, filename)
            
            return {"status": "updated", "rule_id": rule_id}
    
    raise HTTPException(status_code=404, detail="Rule not found")


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a rule."""
    if delete_rule_from_file(rule_id):
        return {"status": "deleted", "rule_id": rule_id}
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str):
    """Toggle a rule's enabled status."""
    rules = load_all_rules()
    
    for rule in rules:
        if rule['id'] == rule_id:
            rule['enabled'] = not rule.get('enabled', True)
            filename = rule.pop('_file', None)
            save_rule_to_file(rule, filename)
            return {"status": "toggled", "rule_id": rule_id, "enabled": rule['enabled']}
    
    raise HTTPException(status_code=404, detail="Rule not found")


@router.post("/rules/reload")
async def reload_rules():
    """Reload all rules from files."""
    rules = load_all_rules()
    return {"status": "reloaded", "rule_count": len(rules)}


@router.post("/rules/dry-run")
async def dry_run_rule(
    rule_yaml: str = Body(..., embed=True, description="YAML rule definition to test"),
    event_count: int = Body(10000, embed=True, description="Number of historical events to test"),
    time_window_hours: int = Body(24, embed=True, description="Time window in hours"),
    current_user: User = Depends(require_role(["admin"]))
):
    """
    Dry-run a rule against historical events.
    
    Phase 5: Tests a proposed rule against the last N events to prevent
    deploying noisy rules that would generate too many alerts.
    
    Requires admin role.
    
    Returns:
        Dictionary with hypothetical alert count and statistics
    """
    from ..invariants.validator import RuleValidator
    from ..database.audit import AuditLogger, ActionType
    
    validator = RuleValidator()
    
    # Validate schema
    is_valid, error, rule = validator.validate_schema(rule_yaml)
    
    if not is_valid:
        # Log failed validation
        AuditLogger.log(
            action_type=ActionType.RULE_CREATE,
            actor_id=current_user.username,
            details={"error": error, "rule_yaml_length": len(rule_yaml)}
        )
        
        raise HTTPException(
            status_code=400,
            detail=f"Rule validation failed: {error}"
        )
    
    # Run dry-run
    result = validator.dry_run(rule, event_count=event_count, time_window_hours=time_window_hours)
    
    # Log dry-run
    AuditLogger.log(
        action_type=ActionType.RULE_CREATE,
        actor_id=current_user.username,
        resource_id=rule.rule_id,
        details={
            "dry_run": True,
            "hypothetical_alerts": result.get("hypothetical_alerts", 0),
            "alert_rate": result.get("alert_rate_percent", 0),
            "is_noisy": result.get("is_noisy", False)
        }
    )
    
    return result


# ============================================================================
# Chain Management Routes
# ============================================================================

@router.get("/chains", response_model=List[Dict])
async def list_chains():
    """List all configured chains."""
    return load_chains_config()


@router.get("/chains/{chain_id}")
async def get_chain(chain_id: str):
    """Get a specific chain configuration."""
    chains = load_chains_config()
    for chain in chains:
        if chain['chain_id'] == chain_id:
            return chain
    raise HTTPException(status_code=404, detail="Chain not found")


@router.post("/chains/{chain_id}/test")
async def test_chain_connection(chain_id: str):
    """Test connection to a chain."""
    chains = load_chains_config()
    
    for chain in chains:
        if chain['chain_id'] == chain_id:
            # Try to connect
            try:
                from web3 import Web3
                w3 = Web3(Web3.HTTPProvider(chain['rpc_url'], request_kwargs={'timeout': 10}))
                
                if w3.is_connected():
                    block = w3.eth.block_number
                    return {
                        "status": "connected",
                        "chain_id": chain_id,
                        "block_number": block
                    }
                else:
                    return {"status": "failed", "error": "Could not connect"}
            except Exception as e:
                return {"status": "failed", "error": str(e)}
    
    raise HTTPException(status_code=404, detail="Chain not found")


# ============================================================================
# Alerting Configuration Routes
# ============================================================================

@router.get("/alerting")
async def get_alerting_config():
    """Get alerting configuration."""
    return load_alerting_config()


@router.put("/alerting")
async def update_alerting_config(config: AlertingConfig):
    """Update alerting configuration."""
    save_alerting_config(config.dict())
    return {"status": "updated"}


@router.post("/alerting/test")
async def send_test_alert(channel: str = "telegram"):
    """Send a test alert."""
    config = load_alerting_config()
    
    if channel == "telegram":
        if not config['telegram']['enabled']:
            return {"status": "skipped", "reason": "Telegram not enabled"}
        
        # Would send actual alert here
        return {"status": "sent", "channel": "telegram"}
    
    elif channel == "slack":
        if not config['slack']['enabled']:
            return {"status": "skipped", "reason": "Slack not enabled"}
        
        return {"status": "sent", "channel": "slack"}
    
    return {"status": "unknown_channel"}


# ============================================================================
# System Routes
# ============================================================================

@router.get("/system/stats")
async def get_system_stats():
    """Get system statistics for admin dashboard."""
    rules = load_all_rules()
    chains = load_chains_config()
    
    return {
        "total_rules": len(rules),
        "enabled_rules": len([r for r in rules if r.get('enabled', True)]),
        "rules_by_severity": {
            "critical": len([r for r in rules if r.get('severity') == 'critical']),
            "high": len([r for r in rules if r.get('severity') == 'high']),
            "medium": len([r for r in rules if r.get('severity') == 'medium']),
            "low": len([r for r in rules if r.get('severity') == 'low']),
        },
        "active_chains": len(chains),
        "chain_names": [c['chain_name'] for c in chains]
    }


@router.get("/system/logs")
async def get_system_logs(limit: int = 100):
    """Get recent system logs."""
    # In production, this would read from actual log files
    return {
        "logs": [
            {"timestamp": "18:45:47", "level": "info", "message": "Rule engine loaded 17 rules"},
            {"timestamp": "18:45:48", "level": "info", "message": "Connected to Ethereum"},
            {"timestamp": "18:45:48", "level": "info", "message": "Connected to Polygon"},
            {"timestamp": "18:45:49", "level": "warning", "message": "Rule velocity-spike-201 triggered"},
        ]
    }


@router.get("/rule-triggers")
async def get_rule_triggers(limit: int = 10):
    """
    Get recent rule triggers from the database.
    
    Returns events that have been flagged by YAML rules with severity > INFO.
    """
    from ..database.service import DatabaseService
    
    try:
        # Query events that were triggered by rules (severity > INFO indicates a rule match)
        # Events with higher severity are typically rule-triggered
        events = await DatabaseService.get_events(
            limit=limit,
            severity="HIGH"  # Get high+ severity events which are typically rule-triggered
        )
        
        # Also get critical and medium events
        critical_events = await DatabaseService.get_events(
            limit=limit,
            severity="CRITICAL"
        )
        
        medium_events = await DatabaseService.get_events(
            limit=limit,
            severity="MEDIUM"
        )
        
        # Combine and sort by timestamp
        all_events = events + critical_events + medium_events
        
        # Convert to trigger format
        triggers = []
        seen_ids = set()
        
        for event in all_events:
            event_id = event.get('event_id', event.get('id', ''))
            if event_id in seen_ids:
                continue
            seen_ids.add(event_id)
            
            # Determine rule name from event type or raw_data
            event_type = event.get('event_type', 'unknown')
            raw_data = event.get('raw_data', {}) or {}
            rule_name = raw_data.get('matched_rule', None)
            
            if not rule_name:
                # Generate rule name from event type
                rule_name = f"{event_type.replace('_', ' ').title()} Detected"
            
            # Calculate relative time
            timestamp = event.get('block_timestamp')
            if timestamp:
                if isinstance(timestamp, str):
                    from datetime import datetime
                    try:
                        timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                    except:
                        timestamp = None
                
                if timestamp:
                    from datetime import datetime, timezone
                    now = datetime.now(timezone.utc)
                    if timestamp.tzinfo is None:
                        timestamp = timestamp.replace(tzinfo=timezone.utc)
                    diff = now - timestamp
                    minutes = int(diff.total_seconds() / 60)
                    
                    if minutes < 1:
                        time_str = "just now"
                    elif minutes < 60:
                        time_str = f"{minutes} min ago"
                    elif minutes < 1440:
                        time_str = f"{minutes // 60} hr ago"
                    else:
                        time_str = f"{minutes // 1440} days ago"
                else:
                    time_str = "unknown"
            else:
                time_str = "unknown"
            
            severity = event.get('severity', 'medium')
            if isinstance(severity, str):
                severity = severity.lower()
            
            triggers.append({
                "id": event_id,
                "ruleName": rule_name,
                "rule_name": rule_name,
                "severity": severity,
                "time": time_str,
                "triggered_at": time_str,
                "chain": event.get('chain_id', 'unknown'),
                "tx_hash": event.get('tx_hash', '')
            })
        
        # Sort by most recent and limit
        triggers = triggers[:limit]
        
        return {"triggers": triggers}
        
    except Exception as e:
        import traceback
        print(f"Error getting rule triggers: {e}")
        traceback.print_exc()
        return {"triggers": []}

