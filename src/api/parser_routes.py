"""
Parser Management API Routes.
Allows viewing and editing event parsers/normalizers.
"""

import os
import yaml
from typing import List, Optional
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from datetime import datetime, timezone

router = APIRouter(prefix="/api/parsers", tags=["parsers"])

PARSERS_FILE = os.path.join(os.path.dirname(__file__), "../../config/parsers.yaml")


# ============================================================================
# Pydantic Models
# ============================================================================

class EVMSignature(BaseModel):
    """EVM event signature parser."""
    signature: str
    name: str
    description: str
    severity: str
    estimated_usd: int = 0
    abi: Optional[str] = None
    category: str
    protocol: Optional[str] = None


class CosmosEvent(BaseModel):
    """Cosmos event type parser."""
    type: str
    name: str
    description: str
    severity: str
    category: str


class MoveEvent(BaseModel):
    """Move-based chain event parser."""
    bridge_functions: List[str]
    severity_patterns: List[dict]


class NearEvent(BaseModel):
    """Near event parser."""
    action_types: List[dict]
    bridge_contracts: List[str]


class SeverityLevel(BaseModel):
    """Severity level definition."""
    value: int
    color: str
    description: str
    response: str


class ParserConfig(BaseModel):
    """Complete parser configuration."""
    version: str
    last_updated: str
    evm_signatures: List[EVMSignature]
    cosmos_events: List[CosmosEvent]
    move_events: MoveEvent
    near_events: NearEvent
    severity_levels: dict
    categories: dict


# ============================================================================
# Helper Functions
# ============================================================================

def load_parsers() -> dict:
    """Load parser configuration from YAML."""
    try:
        with open(PARSERS_FILE, 'r') as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return {"error": "Parser configuration file not found"}
    except Exception as e:
        return {"error": str(e)}


def save_parsers(config: dict) -> bool:
    """Save parser configuration to YAML."""
    try:
        config['last_updated'] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with open(PARSERS_FILE, 'w') as f:
            yaml.dump(config, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
        return True
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to save: {str(e)}")


# ============================================================================
# Routes
# ============================================================================

@router.get("")
async def get_all_parsers():
    """Get complete parser configuration."""
    config = load_parsers()
    if "error" in config:
        raise HTTPException(status_code=500, detail=config["error"])
    return config


@router.get("/evm")
async def get_evm_parsers():
    """Get EVM event signature parsers."""
    config = load_parsers()
    return {
        "count": len(config.get("evm_signatures", [])),
        "parsers": config.get("evm_signatures", [])
    }


@router.get("/evm/{signature}")
async def get_evm_parser(signature: str):
    """Get a specific EVM parser by signature."""
    config = load_parsers()
    for parser in config.get("evm_signatures", []):
        if parser["signature"] == signature:
            return parser
    raise HTTPException(status_code=404, detail="Parser not found")


@router.post("/evm")
async def add_evm_parser(parser: EVMSignature):
    """Add a new EVM event signature parser."""
    config = load_parsers()
    
    # Check if signature already exists
    for existing in config.get("evm_signatures", []):
        if existing["signature"] == parser.signature:
            raise HTTPException(status_code=400, detail="Signature already exists")
    
    config.setdefault("evm_signatures", []).append(parser.dict())
    save_parsers(config)
    
    return {"status": "success", "message": "Parser added", "parser": parser.dict()}


@router.put("/evm/{signature}")
async def update_evm_parser(signature: str, parser: EVMSignature):
    """Update an existing EVM parser."""
    config = load_parsers()
    
    for i, existing in enumerate(config.get("evm_signatures", [])):
        if existing["signature"] == signature:
            config["evm_signatures"][i] = parser.dict()
            save_parsers(config)
            return {"status": "success", "message": "Parser updated"}
    
    raise HTTPException(status_code=404, detail="Parser not found")


@router.delete("/evm/{signature}")
async def delete_evm_parser(signature: str):
    """Delete an EVM parser."""
    config = load_parsers()
    
    original_len = len(config.get("evm_signatures", []))
    config["evm_signatures"] = [
        p for p in config.get("evm_signatures", [])
        if p["signature"] != signature
    ]
    
    if len(config["evm_signatures"]) == original_len:
        raise HTTPException(status_code=404, detail="Parser not found")
    
    save_parsers(config)
    return {"status": "success", "message": "Parser deleted"}


@router.get("/cosmos")
async def get_cosmos_parsers():
    """Get Cosmos event type parsers."""
    config = load_parsers()
    return {
        "count": len(config.get("cosmos_events", [])),
        "parsers": config.get("cosmos_events", [])
    }


@router.post("/cosmos")
async def add_cosmos_parser(parser: CosmosEvent):
    """Add a new Cosmos event parser."""
    config = load_parsers()
    config.setdefault("cosmos_events", []).append(parser.dict())
    save_parsers(config)
    return {"status": "success", "message": "Parser added", "parser": parser.dict()}


@router.get("/move")
async def get_move_parsers():
    """Get Move-based chain parsers (Aptos/Sui)."""
    config = load_parsers()
    return config.get("move_events", {})


@router.put("/move")
async def update_move_parsers(move_events: MoveEvent):
    """Update Move-based chain parsers."""
    config = load_parsers()
    config["move_events"] = move_events.dict()
    save_parsers(config)
    return {"status": "success", "message": "Move parsers updated"}


@router.get("/near")
async def get_near_parsers():
    """Get Near event parsers."""
    config = load_parsers()
    return config.get("near_events", {})


@router.get("/severity")
async def get_severity_levels():
    """Get severity level definitions."""
    config = load_parsers()
    return config.get("severity_levels", {})


@router.get("/categories")
async def get_categories():
    """Get event categories."""
    config = load_parsers()
    return config.get("categories", {})


@router.get("/stats")
async def get_parser_stats():
    """Get parser statistics."""
    config = load_parsers()
    
    evm_by_category = {}
    evm_by_severity = {}
    evm_by_protocol = {}
    
    for parser in config.get("evm_signatures", []):
        # By category
        cat = parser.get("category", "unknown")
        evm_by_category[cat] = evm_by_category.get(cat, 0) + 1
        
        # By severity
        sev = parser.get("severity", "low")
        evm_by_severity[sev] = evm_by_severity.get(sev, 0) + 1
        
        # By protocol
        proto = parser.get("protocol", "generic")
        evm_by_protocol[proto] = evm_by_protocol.get(proto, 0) + 1
    
    return {
        "total_evm_parsers": len(config.get("evm_signatures", [])),
        "total_cosmos_parsers": len(config.get("cosmos_events", [])),
        "evm_by_category": evm_by_category,
        "evm_by_severity": evm_by_severity,
        "evm_by_protocol": evm_by_protocol,
        "last_updated": config.get("last_updated", "unknown")
    }


@router.post("/reload")
async def reload_parsers():
    """
    Reload parsers from config file.
    Call this after manual edits to the YAML file.
    """
    config = load_parsers()
    if "error" in config:
        raise HTTPException(status_code=500, detail=config["error"])
    
    return {
        "status": "success",
        "message": "Parsers reloaded",
        "evm_count": len(config.get("evm_signatures", [])),
        "cosmos_count": len(config.get("cosmos_events", []))
    }

