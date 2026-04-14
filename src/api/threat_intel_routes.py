"""Public Threat Intelligence Feed API."""
from fastapi import APIRouter, Query
from typing import Optional, List
from datetime import datetime, timezone, timedelta
from pydantic import BaseModel, Field
import hashlib
import json

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intelligence"])

# In-memory threat intel store (production would use DB)
_threat_intel = {
    "iocs": [],          # Indicators of compromise
    "malicious_addresses": [],  # Known bad addresses
    "attack_signatures": [],    # Attack pattern signatures
    "feed_updated": None,
}

class IOC(BaseModel):
    id: str = ""
    type: str  # address, tx_hash, contract, domain
    value: str
    chain_id: str = ""
    severity: str = "high"
    tags: List[str] = Field(default_factory=list)
    description: str = ""
    source: str = "sentinel3"
    first_seen: str = ""
    last_seen: str = ""
    confidence: float = 0.0

class AttackSignature(BaseModel):
    id: str = ""
    name: str
    attack_type: str
    description: str
    indicators: List[dict] = Field(default_factory=list)  # list of IOCs
    mitre_tactics: List[str] = Field(default_factory=list)
    severity: str = "high"
    chains: List[str] = Field(default_factory=list)
    first_seen: str = ""
    total_incidents: int = 0
    total_loss_usd: float = 0.0

# --- Seed with known threats ---
def _seed_initial_data():
    now = datetime.now(timezone.utc).isoformat()

    _threat_intel["malicious_addresses"] = [
        {"address": "0x098B716B8Aaf21512996dC57EB0615e2383E2f96", "chain": "ethereum", "label": "Ronin Bridge Exploiter", "severity": "critical", "total_stolen_usd": 624000000, "first_seen": "2022-03-23", "tags": ["bridge-exploit", "lazarus-group"]},
        {"address": "0x629e7Da20197a5429d30da36E77d06CdF796b71A", "chain": "ethereum", "label": "Wormhole Exploiter", "severity": "critical", "total_stolen_usd": 320000000, "first_seen": "2022-02-02", "tags": ["bridge-exploit", "unbacked-mint"]},
        {"address": "0xb624c4222Fae06FE3146830045FcbF4642e3580D", "chain": "ethereum", "label": "Nomad Bridge Exploiter", "severity": "critical", "total_stolen_usd": 190000000, "first_seen": "2022-08-01", "tags": ["bridge-exploit", "replay-attack"]},
        {"address": "0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF", "chain": "ethereum", "label": "Known Mixer Proxy", "severity": "high", "total_stolen_usd": 0, "first_seen": "2023-01-01", "tags": ["mixer", "laundering"]},
    ]

    _threat_intel["attack_signatures"] = [
        {
            "id": "SIG-001",
            "name": "Unbacked Bridge Mint",
            "attack_type": "UNBACKED_MINT",
            "description": "Tokens minted on destination chain without corresponding lock on source chain. Classic bridge exploit pattern.",
            "severity": "critical",
            "chains": ["ethereum", "polygon", "arbitrum", "solana"],
            "mitre_tactics": ["TA0040-Impact"],
            "indicators": [
                {"type": "pattern", "value": "mint_without_lock", "description": "Mint event with no preceding lock"},
                {"type": "invariant", "value": "minted > locked", "description": "Economic invariant violation"},
            ],
            "total_incidents": 12,
            "total_loss_usd": 1134000000,
            "first_seen": "2022-02-02",
        },
        {
            "id": "SIG-002",
            "name": "Sandwich Attack (MEV)",
            "attack_type": "MEV_SANDWICH",
            "description": "Frontrun-victim-backrun pattern in same block extracting value from DEX swaps.",
            "severity": "high",
            "chains": ["ethereum", "polygon", "arbitrum", "base"],
            "mitre_tactics": ["TA0040-Impact", "TA0009-Collection"],
            "indicators": [
                {"type": "pattern", "value": "frontrun_backrun_same_block", "description": "3+ txs in same block with sandwich pattern"},
            ],
            "total_incidents": 8420,
            "total_loss_usd": 45000000,
            "first_seen": "2020-01-15",
        },
        {
            "id": "SIG-003",
            "name": "Flash Loan Attack",
            "attack_type": "FLASH_LOAN_EXPLOIT",
            "description": "Borrow-exploit-repay in single transaction/block, often targeting oracle manipulation.",
            "severity": "critical",
            "chains": ["ethereum", "polygon", "avalanche", "bsc"],
            "mitre_tactics": ["TA0040-Impact"],
            "indicators": [
                {"type": "pattern", "value": "borrow_exploit_repay_same_block"},
                {"type": "event_sequence", "value": "FLASH_BORROW -> SWAP -> TRANSFER -> REPAY"},
            ],
            "total_incidents": 340,
            "total_loss_usd": 890000000,
            "first_seen": "2020-02-15",
        },
        {
            "id": "SIG-004",
            "name": "Governance Takeover",
            "attack_type": "GOVERNANCE_ATTACK",
            "description": "Flash loan used to acquire voting power and pass malicious governance proposals.",
            "severity": "critical",
            "chains": ["ethereum"],
            "mitre_tactics": ["TA0004-PrivilegeEscalation"],
            "indicators": [
                {"type": "pattern", "value": "flash_borrow_then_vote"},
            ],
            "total_incidents": 15,
            "total_loss_usd": 180000000,
            "first_seen": "2022-04-17",
        },
    ]

    _threat_intel["feed_updated"] = now

_seed_initial_data()

@router.get("/feed")
async def get_threat_feed(
    severity: Optional[str] = None,
    chain: Optional[str] = None,
    type: Optional[str] = None,
    limit: int = Query(default=100, le=500),
):
    """Get the public threat intelligence feed."""
    # Combine from live incident data
    all_items = []

    for addr in _threat_intel["malicious_addresses"]:
        if severity and addr.get("severity") != severity:
            continue
        if chain and addr.get("chain") != chain:
            continue
        all_items.append({"type": "malicious_address", **addr})

    for sig in _threat_intel["attack_signatures"]:
        if severity and sig.get("severity") != severity:
            continue
        if chain and chain not in sig.get("chains", []):
            continue
        all_items.append({"type": "attack_signature", **sig})

    return {
        "feed_version": "1.0",
        "updated_at": _threat_intel["feed_updated"],
        "total_items": len(all_items),
        "items": all_items[:limit],
    }

@router.get("/addresses")
async def get_malicious_addresses(chain: Optional[str] = None, limit: int = 100):
    """Get known malicious addresses."""
    addrs = _threat_intel["malicious_addresses"]
    if chain:
        addrs = [a for a in addrs if a.get("chain") == chain]
    return {"count": len(addrs), "addresses": addrs[:limit]}

@router.get("/signatures")
async def get_attack_signatures(attack_type: Optional[str] = None):
    """Get attack pattern signatures."""
    sigs = _threat_intel["attack_signatures"]
    if attack_type:
        sigs = [s for s in sigs if s.get("attack_type") == attack_type]
    return {"count": len(sigs), "signatures": sigs}

@router.get("/check/{address}")
async def check_address(address: str):
    """Check if an address is in the threat database."""
    address_lower = address.lower()
    for addr in _threat_intel["malicious_addresses"]:
        if addr["address"].lower() == address_lower:
            return {"found": True, "threat": addr}

    # Also check from live incidents
    try:
        from src.database.service import DatabaseService
        events = await DatabaseService.query_events_by_address(address=address, limit=10)
        if events:
            return {"found": False, "activity_detected": True, "event_count": len(events)}
    except Exception:
        pass

    return {"found": False, "activity_detected": False}

@router.post("/report")
async def report_threat(ioc: IOC):
    """Submit a new IOC to the threat intel feed."""
    ioc.id = hashlib.sha256(f"{ioc.type}:{ioc.value}".encode()).hexdigest()[:12]
    ioc.first_seen = ioc.first_seen or datetime.now(timezone.utc).isoformat()
    ioc.last_seen = datetime.now(timezone.utc).isoformat()

    _threat_intel["iocs"].append(ioc.dict())
    _threat_intel["feed_updated"] = datetime.now(timezone.utc).isoformat()

    return {"status": "accepted", "ioc_id": ioc.id}
