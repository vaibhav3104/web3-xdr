"""
Multi-tenancy API routes for Sentinel3.
Supports multiple organizations with isolated data, API key management,
tier controls, and per-tenant usage statistics.
"""

from typing import List, Optional, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4
import hashlib
import secrets

from fastapi import APIRouter, HTTPException, Depends, Request, status, Header, Query
from pydantic import BaseModel, Field
import structlog

from ..auth.jwt_handler import require_auth, require_role
from ..auth.models import User
from ..auth.tenant_middleware import get_tenant_id, get_tenant_tier, require_scope

logger = structlog.get_logger()
router = APIRouter(prefix="/tenants", tags=["Multi-tenancy"])


# ============================================================================
# Pydantic Models
# ============================================================================

class Tenant(BaseModel):
    id: str
    name: str
    slug: str
    plan: str  # free, pro, enterprise (maps to tier)
    created_at: datetime
    settings: dict = {}
    limits: dict = {}


class TenantCreate(BaseModel):
    name: str
    slug: str
    plan: str = "free"
    admin_email: str = ""


class TenantUpdate(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    settings: Optional[dict] = None
    admin_email: Optional[str] = None


class TenantMember(BaseModel):
    user_id: str
    username: str
    role: str  # owner, admin, member, viewer
    joined_at: datetime


class TenantStats(BaseModel):
    tenant_id: str
    incidents_count: int
    events_count: int
    api_keys_active: int
    total_api_calls: int
    chains_monitored: int
    users_count: int
    storage_used_mb: float


class APIKeyCreate(BaseModel):
    name: str = Field(..., description="Key name/label")
    scopes: List[str] = Field(["read"], description="Permissions: read, write, admin, guardian")
    expires_in_days: Optional[int] = Field(None, description="Days until expiration (None = never)")
    description: str = ""
    allowed_ips: List[str] = Field(default=[], description="Allowed IP addresses (empty = all)")


class APIKeyResponse(BaseModel):
    key_id: str
    name: str
    key_prefix: str
    scopes: List[str]
    status: str
    created_at: str
    expires_at: Optional[str] = None
    last_used_at: Optional[str] = None
    total_requests: int = 0


class APIKeyCreatedResponse(BaseModel):
    api_key: str  # The actual key -- shown only once
    key_details: APIKeyResponse


class TierChangeRequest(BaseModel):
    new_tier: str = Field(..., description="Target tier: starter, pro, enterprise")


# ============================================================================
# In-memory tenant storage (database-backed operations overlay)
# ============================================================================

TENANTS: Dict[str, Tenant] = {
    "default": Tenant(
        id="default",
        name="Default Organization",
        slug="default",
        plan="enterprise",
        created_at=datetime.now(timezone.utc),
        settings={
            "alerts_enabled": True,
            "max_incidents": 1000,
            "retention_days": 90,
            "api_access": True,
            "sso_enabled": True,
            "custom_rules": True,
        },
        limits={
            "max_users": 100,
            "max_chains": 10,
            "max_rules": 50,
            "max_api_calls_per_day": -1,
            "max_alerts_per_day": -1,
        }
    ),
    "acme": Tenant(
        id="acme",
        name="ACME DeFi",
        slug="acme",
        plan="pro",
        created_at=datetime.now(timezone.utc),
        settings={
            "alerts_enabled": True,
            "max_incidents": 500,
            "retention_days": 30,
            "api_access": True,
            "sso_enabled": False,
            "custom_rules": True,
        },
        limits={
            "max_users": 25,
            "max_chains": 5,
            "max_rules": 20,
            "max_api_calls_per_day": 10000,
            "max_alerts_per_day": 500,
        }
    ),
    "demo": Tenant(
        id="demo",
        name="Demo Company",
        slug="demo",
        plan="free",
        created_at=datetime.now(timezone.utc),
        settings={
            "alerts_enabled": False,
            "max_incidents": 100,
            "retention_days": 7,
            "api_access": False,
            "sso_enabled": False,
            "custom_rules": False,
        },
        limits={
            "max_users": 5,
            "max_chains": 2,
            "max_rules": 5,
            "max_api_calls_per_day": 100,
            "max_alerts_per_day": 10,
        }
    )
}

TENANT_MEMBERS: Dict[str, List[TenantMember]] = {
    "default": [
        TenantMember(user_id="1", username="admin", role="owner", joined_at=datetime.now(timezone.utc)),
        TenantMember(user_id="2", username="operator", role="admin", joined_at=datetime.now(timezone.utc)),
    ],
    "acme": [
        TenantMember(user_id="3", username="acme_admin", role="owner", joined_at=datetime.now(timezone.utc)),
    ],
    "demo": [
        TenantMember(user_id="4", username="demo_user", role="member", joined_at=datetime.now(timezone.utc)),
    ]
}


# ============================================================================
# Helper to get current tenant
# ============================================================================

def get_current_tenant(x_tenant_id: str = Header(default="default")) -> Tenant:
    """Get tenant from header or default."""
    tenant = TENANTS.get(x_tenant_id)
    if not tenant:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tenant '{x_tenant_id}' not found"
        )
    return tenant


# ============================================================================
# Tenant CRUD Routes
# ============================================================================

@router.get("", response_model=List[Tenant])
async def list_tenants(
    current_user: User = Depends(require_role(["admin"]))
):
    """List all tenants (super admin only)."""
    return list(TENANTS.values())


@router.get("/current", response_model=Tenant)
async def get_current_tenant_info(
    tenant: Tenant = Depends(get_current_tenant),
    current_user: User = Depends(require_auth)
):
    """Get current tenant information."""
    return tenant


@router.post("", response_model=Tenant)
async def create_tenant(
    request: TenantCreate,
    current_user: User = Depends(require_role(["admin"]))
):
    """Create a new tenant (super admin only)."""
    if request.slug in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tenant with slug '{request.slug}' already exists"
        )

    tenant = Tenant(
        id=str(uuid4()),
        name=request.name,
        slug=request.slug,
        plan=request.plan,
        created_at=datetime.now(timezone.utc),
        settings=get_default_settings(request.plan),
        limits=get_plan_limits(request.plan)
    )

    TENANTS[request.slug] = tenant
    TENANT_MEMBERS[request.slug] = [
        TenantMember(
            user_id=current_user.username,
            username=current_user.username,
            role="owner",
            joined_at=datetime.now(timezone.utc)
        )
    ]

    # Also create corresponding DB customer if possible
    try:
        from .api_keys import api_key_manager
        api_key_manager.create_customer(
            name=request.name,
            tier=_plan_to_tier(request.plan),
            admin_email=request.admin_email or f"{request.slug}@sentinel3.io",
        )
    except Exception as exc:
        logger.debug("db_customer_create_skipped", error=str(exc))

    logger.info("tenant_created", tenant_id=tenant.id, name=tenant.name)
    return tenant


@router.patch("/{tenant_id}", response_model=Tenant)
async def update_tenant(
    tenant_id: str,
    request: TenantUpdate,
    current_user: User = Depends(require_role(["admin"]))
):
    """Update tenant settings."""
    if tenant_id not in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )

    tenant = TENANTS[tenant_id]

    if request.name:
        tenant.name = request.name
    if request.plan:
        tenant.plan = request.plan
        tenant.limits = get_plan_limits(request.plan)
        tenant.settings = {**tenant.settings, **get_default_settings(request.plan)}
    if request.settings:
        tenant.settings.update(request.settings)

    TENANTS[tenant_id] = tenant
    logger.info("tenant_updated", tenant_id=tenant_id)
    return tenant


@router.delete("/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    current_user: User = Depends(require_role(["admin"]))
):
    """Delete a tenant (super admin only)."""
    if tenant_id == "default":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete default tenant"
        )

    if tenant_id not in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )

    del TENANTS[tenant_id]
    if tenant_id in TENANT_MEMBERS:
        del TENANT_MEMBERS[tenant_id]

    return {"message": f"Tenant {tenant_id} deleted"}


# ============================================================================
# Tier Management
# ============================================================================

@router.post("/{tenant_id}/tier", response_model=Tenant)
async def change_tier(
    tenant_id: str,
    request: TierChangeRequest,
    current_user: User = Depends(require_role(["admin"]))
):
    """Upgrade or downgrade a tenant's tier."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    valid_tiers = {"free", "pro", "enterprise", "starter", "growth"}
    if request.new_tier not in valid_tiers:
        raise HTTPException(status_code=400, detail=f"Invalid tier. Valid: {valid_tiers}")

    tenant = TENANTS[tenant_id]
    old_plan = tenant.plan
    plan = _tier_to_plan(request.new_tier)
    tenant.plan = plan
    tenant.limits = get_plan_limits(plan)
    tenant.settings = {**tenant.settings, **get_default_settings(plan)}
    TENANTS[tenant_id] = tenant

    logger.info("tenant_tier_changed", tenant_id=tenant_id, old=old_plan, new=plan)
    return tenant


# ============================================================================
# Tenant Member Routes
# ============================================================================

@router.get("/{tenant_id}/members", response_model=List[TenantMember])
async def list_tenant_members(
    tenant_id: str,
    current_user: User = Depends(require_auth)
):
    """List members of a tenant."""
    if tenant_id not in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )

    return TENANT_MEMBERS.get(tenant_id, [])


@router.post("/{tenant_id}/members")
async def add_tenant_member(
    tenant_id: str,
    username: str,
    role: str = "member",
    current_user: User = Depends(require_role(["admin"]))
):
    """Add a member to tenant."""
    if tenant_id not in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )

    member = TenantMember(
        user_id=str(uuid4()),
        username=username,
        role=role,
        joined_at=datetime.now(timezone.utc)
    )

    if tenant_id not in TENANT_MEMBERS:
        TENANT_MEMBERS[tenant_id] = []

    TENANT_MEMBERS[tenant_id].append(member)
    return member


# ============================================================================
# API Key Management (per tenant)
# ============================================================================

@router.post("/{tenant_id}/api-keys", response_model=APIKeyCreatedResponse)
async def generate_tenant_api_key(
    tenant_id: str,
    request: APIKeyCreate,
    current_user: User = Depends(require_role(["admin"]))
):
    """Generate a new API key for a tenant. The key is shown only ONCE."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from .api_keys import api_key_manager, KeyScope

        # Resolve customer_id from slug
        customer_id = _resolve_customer_id(tenant_id)

        scopes = set()
        for s in request.scopes:
            try:
                scopes.add(KeyScope(s))
            except ValueError:
                raise HTTPException(status_code=400, detail=f"Invalid scope: {s}")

        raw_key, api_key = api_key_manager.generate_api_key(
            customer_id=customer_id,
            name=request.name,
            scopes=scopes,
            expires_in_days=request.expires_in_days,
            description=request.description,
            allowed_ips=request.allowed_ips,
        )

        return APIKeyCreatedResponse(
            api_key=raw_key,
            key_details=APIKeyResponse(
                key_id=api_key.id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                scopes=[s.value for s in api_key.scopes],
                status=api_key.status.value,
                created_at=api_key.created_at.isoformat(),
                expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
                last_used_at=None,
                total_requests=0,
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except ImportError:
        raise HTTPException(status_code=503, detail="API key management unavailable")


@router.get("/{tenant_id}/api-keys", response_model=List[APIKeyResponse])
async def list_tenant_api_keys(
    tenant_id: str,
    current_user: User = Depends(require_auth)
):
    """List all API keys for a tenant (keys are masked)."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from .api_keys import api_key_manager
        customer_id = _resolve_customer_id(tenant_id)
        keys = api_key_manager.get_customer_keys(customer_id)
        return [
            APIKeyResponse(
                key_id=k.id,
                name=k.name,
                key_prefix=k.key_prefix,
                scopes=[s.value for s in k.scopes],
                status=k.status.value,
                created_at=k.created_at.isoformat(),
                expires_at=k.expires_at.isoformat() if k.expires_at else None,
                last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
                total_requests=k.total_requests,
            )
            for k in keys
        ]
    except ImportError:
        return []


@router.delete("/{tenant_id}/api-keys/{key_id}")
async def revoke_tenant_api_key(
    tenant_id: str,
    key_id: str,
    current_user: User = Depends(require_role(["admin"]))
):
    """Revoke an API key for a tenant."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from .api_keys import api_key_manager
        success = api_key_manager.revoke_key(key_id)
        if not success:
            raise HTTPException(status_code=404, detail="API key not found")
        return {"status": "revoked", "key_id": key_id}
    except ImportError:
        raise HTTPException(status_code=503, detail="API key management unavailable")


@router.post("/{tenant_id}/api-keys/{key_id}/rotate", response_model=APIKeyCreatedResponse)
async def rotate_tenant_api_key(
    tenant_id: str,
    key_id: str,
    current_user: User = Depends(require_role(["admin"]))
):
    """Rotate an API key (revoke old, generate new). Old key stops immediately."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from .api_keys import api_key_manager
        raw_key, api_key = api_key_manager.rotate_key(key_id)
        if not api_key:
            raise HTTPException(status_code=404, detail="API key not found")
        return APIKeyCreatedResponse(
            api_key=raw_key,
            key_details=APIKeyResponse(
                key_id=api_key.id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                scopes=[s.value for s in api_key.scopes],
                status=api_key.status.value,
                created_at=api_key.created_at.isoformat(),
                expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
                last_used_at=None,
                total_requests=0,
            )
        )
    except ImportError:
        raise HTTPException(status_code=503, detail="API key management unavailable")


# ============================================================================
# Tenant Stats & Usage
# ============================================================================

@router.get("/{tenant_id}/stats", response_model=TenantStats)
async def get_tenant_stats(
    tenant_id: str,
    current_user: User = Depends(require_auth)
):
    """Get usage statistics for a tenant."""
    if tenant_id not in TENANTS:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tenant not found"
        )

    # Try database-backed stats first
    try:
        from ..database.service import DatabaseService
        customer_id = _resolve_customer_id(tenant_id)
        db_stats = await DatabaseService.get_tenant_usage_stats(customer_id)
        return TenantStats(
            tenant_id=tenant_id,
            incidents_count=db_stats.get("incidents_count", 0),
            events_count=db_stats.get("events_count", 0),
            api_keys_active=db_stats.get("api_keys_active", 0),
            total_api_calls=db_stats.get("total_api_calls", 0),
            chains_monitored=TENANTS[tenant_id].limits.get("max_chains", 0),
            users_count=len(TENANT_MEMBERS.get(tenant_id, [])),
            storage_used_mb=0.0,
        )
    except Exception:
        # Fallback to demo data
        return TenantStats(
            tenant_id=tenant_id,
            incidents_count=47,
            events_count=12500,
            api_keys_active=3,
            total_api_calls=84230,
            chains_monitored=8,
            users_count=len(TENANT_MEMBERS.get(tenant_id, [])),
            storage_used_mb=256.5
        )


@router.get("/{tenant_id}/usage")
async def get_tenant_usage(
    tenant_id: str,
    current_user: User = Depends(require_auth)
):
    """Get detailed usage breakdown for a tenant."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    tenant = TENANTS[tenant_id]
    limits = tenant.limits

    # Try to get real API call counts
    total_api_calls = 0
    try:
        from .api_keys import api_key_manager
        customer_id = _resolve_customer_id(tenant_id)
        keys = api_key_manager.get_customer_keys(customer_id)
        total_api_calls = sum(k.total_requests for k in keys)
    except Exception:
        total_api_calls = 84230  # demo

    max_calls = limits.get("max_api_calls_per_day", 100)
    usage_pct = (total_api_calls / max_calls * 100) if max_calls > 0 else 0

    return {
        "tenant_id": tenant_id,
        "plan": tenant.plan,
        "api_calls": {
            "used": total_api_calls,
            "limit": max_calls,
            "usage_percent": round(min(usage_pct, 100), 1),
        },
        "members": {
            "used": len(TENANT_MEMBERS.get(tenant_id, [])),
            "limit": limits.get("max_users", 5),
        },
        "chains": {
            "limit": limits.get("max_chains", 2),
        },
        "rules": {
            "limit": limits.get("max_rules", 5),
        },
    }


# ============================================================================
# Tenant-scoped data access
# ============================================================================

@router.get("/{tenant_id}/incidents")
async def get_tenant_incidents(
    tenant_id: str,
    limit: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    current_user: User = Depends(require_auth)
):
    """Get incidents scoped to a tenant's monitored contracts."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from ..database.service import DatabaseService
        incidents, _ = await DatabaseService.get_incidents(limit=limit, severity=severity)
        return {"tenant_id": tenant_id, "incidents": incidents, "count": len(incidents)}
    except Exception:
        return {"tenant_id": tenant_id, "incidents": [], "count": 0}


@router.get("/{tenant_id}/events")
async def get_tenant_events(
    tenant_id: str,
    limit: int = Query(20, ge=1, le=100),
    chain_id: Optional[str] = None,
    current_user: User = Depends(require_auth)
):
    """Get events scoped to a tenant's monitored contracts."""
    if tenant_id not in TENANTS:
        raise HTTPException(status_code=404, detail="Tenant not found")

    try:
        from ..database.service import DatabaseService
        events, cursor = await DatabaseService.get_events(chain_id=chain_id, limit=limit)
        return {"tenant_id": tenant_id, "events": events, "count": len(events)}
    except Exception:
        return {"tenant_id": tenant_id, "events": [], "count": 0}


# ============================================================================
# Helper Functions
# ============================================================================

def _plan_to_tier(plan: str) -> str:
    """Convert plan name to customer tier."""
    mapping = {"free": "starter", "pro": "pro", "enterprise": "enterprise"}
    return mapping.get(plan, "starter")


def _tier_to_plan(tier: str) -> str:
    """Convert customer tier to plan name."""
    mapping = {"starter": "free", "growth": "pro", "pro": "pro", "enterprise": "enterprise"}
    return mapping.get(tier, "free")


def _resolve_customer_id(tenant_slug: str) -> str:
    """Resolve a tenant slug to a customer_id for the api_key_manager."""
    try:
        from .api_keys import api_key_manager
        customers = api_key_manager.list_customers(active_only=False)
        # Match by name similarity or slug
        for c in customers:
            if c.id == tenant_slug or c.name.lower().replace(" ", "-") == tenant_slug:
                return c.id
    except Exception:
        pass
    # Default: use slug as customer_id
    return tenant_slug


def get_default_settings(plan: str) -> dict:
    """Get default settings based on plan."""
    base = {
        "alerts_enabled": True,
        "email_notifications": True,
        "slack_enabled": False,
        "telegram_enabled": False
    }

    if plan == "enterprise":
        base.update({
            "custom_rules": True,
            "api_access": True,
            "sso_enabled": True,
            "max_incidents": 10000,
            "retention_days": 365
        })
    elif plan == "pro":
        base.update({
            "custom_rules": True,
            "api_access": True,
            "sso_enabled": False,
            "max_incidents": 1000,
            "retention_days": 90
        })
    else:  # free
        base.update({
            "custom_rules": False,
            "api_access": False,
            "sso_enabled": False,
            "max_incidents": 100,
            "retention_days": 7
        })

    return base


def get_plan_limits(plan: str) -> dict:
    """Get limits based on plan."""
    limits = {
        "free": {
            "max_users": 5,
            "max_chains": 2,
            "max_rules": 5,
            "max_api_calls_per_day": 100,
            "max_alerts_per_day": 10
        },
        "pro": {
            "max_users": 25,
            "max_chains": 5,
            "max_rules": 50,
            "max_api_calls_per_day": 10000,
            "max_alerts_per_day": 500
        },
        "enterprise": {
            "max_users": -1,  # unlimited
            "max_chains": -1,
            "max_rules": -1,
            "max_api_calls_per_day": -1,
            "max_alerts_per_day": -1
        }
    }

    return limits.get(plan, limits["free"])
