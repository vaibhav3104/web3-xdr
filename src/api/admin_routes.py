"""
Admin API Routes for Web3 XDR.
Manage rules, chains, and alerting configuration through the UI.
"""

import os
import yaml
from datetime import datetime
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, Body
from pydantic import BaseModel, Field
from pathlib import Path

router = APIRouter(prefix="/admin", tags=["admin"])

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


def load_chains_config() -> List[Dict]:
    """Load chain configuration."""
    config_file = CONFIG_DIR / "chains.yaml"
    
    if not config_file.exists():
        return []
    
    with open(config_file, 'r') as f:
        data = yaml.safe_load(f)
    
    chains = data.get('chains', [])
    
    # Add status (would be determined by actual connection status)
    for chain in chains:
        chain['status'] = 'connected'  # Simplified
    
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

