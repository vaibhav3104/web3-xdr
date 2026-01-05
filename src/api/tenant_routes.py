"""
Multi-tenancy API routes for Sentinel3.
Supports multiple organizations with isolated data.
"""

from typing import List, Optional
from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Depends, status, Header
from pydantic import BaseModel
import structlog

from ..auth.jwt_handler import require_auth, require_role
from ..auth.models import User

logger = structlog.get_logger()
router = APIRouter(prefix="/tenants", tags=["Multi-tenancy"])


# ============================================================================
# Models
# ============================================================================

class Tenant(BaseModel):
    id: str
    name: str
    slug: str
    plan: str  # free, pro, enterprise
    created_at: datetime
    settings: dict = {}
    limits: dict = {}
    
class TenantCreate(BaseModel):
    name: str
    slug: str
    plan: str = "free"
    
class TenantUpdate(BaseModel):
    name: Optional[str] = None
    plan: Optional[str] = None
    settings: Optional[dict] = None

class TenantMember(BaseModel):
    user_id: str
    username: str
    role: str  # owner, admin, member, viewer
    joined_at: datetime

class TenantStats(BaseModel):
    tenant_id: str
    incidents_count: int
    events_count: int
    chains_monitored: int
    users_count: int
    storage_used_mb: float


# ============================================================================
# In-memory tenant storage (would be database in production)
# ============================================================================

TENANTS = {
    "default": Tenant(
        id="default",
        name="Default Organization",
        slug="default",
        plan="enterprise",
        created_at=datetime.utcnow(),
        settings={
            "alerts_enabled": True,
            "max_incidents": 1000,
            "retention_days": 90
        },
        limits={
            "max_users": 100,
            "max_chains": 10,
            "max_rules": 50
        }
    ),
    "acme": Tenant(
        id="acme",
        name="ACME DeFi",
        slug="acme",
        plan="pro",
        created_at=datetime.utcnow(),
        settings={
            "alerts_enabled": True,
            "max_incidents": 500,
            "retention_days": 30
        },
        limits={
            "max_users": 25,
            "max_chains": 5,
            "max_rules": 20
        }
    ),
    "demo": Tenant(
        id="demo",
        name="Demo Company",
        slug="demo",
        plan="free",
        created_at=datetime.utcnow(),
        settings={
            "alerts_enabled": False,
            "max_incidents": 100,
            "retention_days": 7
        },
        limits={
            "max_users": 5,
            "max_chains": 2,
            "max_rules": 5
        }
    )
}

TENANT_MEMBERS = {
    "default": [
        TenantMember(user_id="1", username="admin", role="owner", joined_at=datetime.utcnow()),
        TenantMember(user_id="2", username="operator", role="admin", joined_at=datetime.utcnow()),
    ],
    "acme": [
        TenantMember(user_id="3", username="acme_admin", role="owner", joined_at=datetime.utcnow()),
    ],
    "demo": [
        TenantMember(user_id="4", username="demo_user", role="member", joined_at=datetime.utcnow()),
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
        created_at=datetime.utcnow(),
        settings=get_default_settings(request.plan),
        limits=get_plan_limits(request.plan)
    )
    
    TENANTS[request.slug] = tenant
    TENANT_MEMBERS[request.slug] = [
        TenantMember(
            user_id=current_user.username,
            username=current_user.username,
            role="owner",
            joined_at=datetime.utcnow()
        )
    ]
    
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
    if request.settings:
        tenant.settings.update(request.settings)
    
    TENANTS[tenant_id] = tenant
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
        joined_at=datetime.utcnow()
    )
    
    if tenant_id not in TENANT_MEMBERS:
        TENANT_MEMBERS[tenant_id] = []
    
    TENANT_MEMBERS[tenant_id].append(member)
    return member


# ============================================================================
# Tenant Stats
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
    
    # In production, this would query the database
    return TenantStats(
        tenant_id=tenant_id,
        incidents_count=47,
        events_count=12500,
        chains_monitored=8,
        users_count=len(TENANT_MEMBERS.get(tenant_id, [])),
        storage_used_mb=256.5
    )


# ============================================================================
# Helper Functions
# ============================================================================

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

