"""API routes for custom invariant DSL management."""

import os
from typing import List, Any

import structlog
import yaml
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = structlog.get_logger()

router = APIRouter(prefix="/api/invariants/custom", tags=["invariants-dsl"])

CUSTOM_INVARIANTS_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "config", "custom_invariants"
)


# ============================================================================
# Request/Response Models
# ============================================================================


class InvariantConditionSchema(BaseModel):
    field: str
    operator: str
    value: Any


class CustomInvariantSchema(BaseModel):
    name: str
    description: str = ""
    type: str = "threshold"
    severity: str = "medium"
    enabled: bool = True
    chains: List[str] = Field(default_factory=list)
    event_types: List[str] = Field(default_factory=list)
    conditions: List[InvariantConditionSchema] = Field(default_factory=list)
    match_mode: str = "all"
    cooldown_seconds: int = 60
    confidence: float = 0.8


# ============================================================================
# Endpoints
# ============================================================================


@router.get("/")
async def list_custom_invariants():
    """List all custom YAML-defined invariants."""
    from src.invariants.dsl import DSLLoader

    try:
        defs = DSLLoader.load_directory(CUSTOM_INVARIANTS_DIR)
        return {
            "count": len(defs),
            "invariants": [
                {
                    "name": d.name,
                    "description": d.description,
                    "type": d.invariant_type,
                    "severity": d.severity,
                    "enabled": d.enabled,
                    "chains": d.chains,
                    "event_types": d.event_types,
                    "conditions": len(d.conditions),
                    "match_mode": d.match_mode,
                    "cooldown_seconds": d.cooldown_seconds,
                    "confidence": d.confidence,
                }
                for d in defs
            ],
        }
    except Exception as e:
        logger.error("list_custom_invariants_error", error=str(e))
        return {"count": 0, "invariants": [], "error": str(e)}


@router.post("/")
async def create_custom_invariant(invariant: CustomInvariantSchema):
    """Create a new custom invariant (saves to YAML)."""
    os.makedirs(CUSTOM_INVARIANTS_DIR, exist_ok=True)

    inv_dict = {
        "name": invariant.name,
        "description": invariant.description,
        "type": invariant.type,
        "severity": invariant.severity,
        "enabled": invariant.enabled,
        "chains": invariant.chains,
        "event_types": invariant.event_types,
        "conditions": [
            {"field": c.field, "operator": c.operator, "value": c.value}
            for c in invariant.conditions
        ],
        "match_mode": invariant.match_mode,
        "cooldown_seconds": invariant.cooldown_seconds,
        "confidence": invariant.confidence,
    }

    filename = f"{invariant.name.replace(' ', '_').lower()}.yaml"
    filepath = os.path.join(CUSTOM_INVARIANTS_DIR, filename)

    with open(filepath, "w") as f:
        yaml.dump({"invariants": [inv_dict]}, f, default_flow_style=False)

    logger.info("custom_invariant_created", name=invariant.name, file=filename)
    return {"status": "created", "file": filename, "invariant": inv_dict}


@router.post("/validate")
async def validate_invariant_yaml(body: dict):
    """Validate a YAML invariant definition without saving."""
    from src.invariants.dsl import DSLLoader

    try:
        yaml_str = body.get("yaml", "")
        defs = DSLLoader.load_string(yaml_str)
        return {
            "valid": True,
            "invariant_count": len(defs),
            "invariants": [
                {"name": d.name, "conditions": len(d.conditions)} for d in defs
            ],
        }
    except Exception as e:
        return {"valid": False, "error": str(e)}


@router.delete("/{name}")
async def delete_custom_invariant(name: str):
    """Delete a custom invariant YAML file."""
    filename = f"{name.replace(' ', '_').lower()}.yaml"
    filepath = os.path.join(CUSTOM_INVARIANTS_DIR, filename)
    if os.path.exists(filepath):
        os.remove(filepath)
        logger.info("custom_invariant_deleted", name=name, file=filename)
        return {"status": "deleted", "name": name}
    raise HTTPException(status_code=404, detail=f"Invariant '{name}' not found")
