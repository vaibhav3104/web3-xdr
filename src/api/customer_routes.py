"""
Customer Onboarding and API Key Management Routes
==================================================

REST API endpoints for:
1. Customer registration and management
2. API key generation and rotation
3. Contract configuration
4. Usage statistics
"""

from fastapi import APIRouter, HTTPException, Depends, Body, Query
from pydantic import BaseModel, Field
from typing import List, Optional, Set, Dict, Any
from datetime import datetime, timezone
import structlog

from .api_keys import (
    api_key_manager,
    APIKey,
    Customer,
    KeyScope,
    KeyStatus,
    verify_api_key,
    require_scope
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/customers", tags=["customers"])

# =============================================================================
# Request/Response Models
# =============================================================================

class CreateCustomerRequest(BaseModel):
    """Request to create a new customer."""
    name: str = Field(..., description="Customer/Organization name")
    tier: str = Field("starter", description="Subscription tier: starter, growth, enterprise")
    admin_email: str = Field(..., description="Admin email address")
    alert_emails: List[str] = Field(default=[], description="Email addresses for alerts")
    telegram_chat_id: Optional[str] = Field(None, description="Telegram chat ID for alerts")
    slack_webhook: Optional[str] = Field(None, description="Slack webhook URL for alerts")


class CustomerResponse(BaseModel):
    """Customer details response."""
    id: str
    name: str
    tier: str
    active: bool
    created_at: str
    max_api_keys: int
    max_contracts: int
    max_chains: int
    features: List[str]
    admin_email: str
    contracts_count: int


class GenerateAPIKeyRequest(BaseModel):
    """Request to generate an API key."""
    name: str = Field(..., description="Key name/label")
    scopes: List[str] = Field(
        ["read"],
        description="Permissions: read, write, admin, guardian"
    )
    expires_in_days: Optional[int] = Field(
        None,
        description="Days until expiration (None = never)"
    )
    description: str = Field("", description="Key description")
    allowed_ips: List[str] = Field(
        default=[],
        description="Allowed IP addresses (empty = all)"
    )


class APIKeyResponse(BaseModel):
    """API key details (without the actual key)."""
    id: str
    name: str
    key_prefix: str
    scopes: List[str]
    status: str
    created_at: str
    expires_at: Optional[str]
    last_used_at: Optional[str]
    total_requests: int
    rate_limit: int


class APIKeyCreatedResponse(BaseModel):
    """Response when API key is created (includes the key ONCE)."""
    api_key: str  # The actual key - shown only once!
    key_details: APIKeyResponse


class AddContractRequest(BaseModel):
    """Request to add a contract for monitoring."""
    chain_id: str = Field(..., description="Chain: ethereum, polygon, arbitrum, etc.")
    contract_address: str = Field(..., description="Contract address")
    contract_type: str = Field("defi", description="Type: defi, bridge, token")
    contract_name: str = Field("", description="Human-readable name")
    metadata: Dict[str, Any] = Field(default={}, description="Additional metadata")


class ContractResponse(BaseModel):
    """Contract details."""
    chain_id: str
    address: str
    type: str
    name: str
    added_at: str


# =============================================================================
# Customer Management Endpoints
# =============================================================================

@router.post("", response_model=CustomerResponse)
async def create_customer(request: CreateCustomerRequest):
    """
    Register a new customer.
    
    This is typically called by Sentinel3 admins or self-service signup.
    """
    try:
        customer = api_key_manager.create_customer(
            name=request.name,
            tier=request.tier,
            admin_email=request.admin_email,
            alert_emails=request.alert_emails,
            telegram_chat_id=request.telegram_chat_id,
            slack_webhook=request.slack_webhook
        )
        
        return CustomerResponse(
            id=customer.id,
            name=customer.name,
            tier=customer.tier,
            active=customer.active,
            created_at=customer.created_at.isoformat(),
            max_api_keys=customer.max_api_keys,
            max_contracts=customer.max_contracts,
            max_chains=customer.max_chains,
            features=list(customer.features),
            admin_email=customer.admin_email,
            contracts_count=len(customer.contracts)
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=List[CustomerResponse])
async def list_customers(
    active_only: bool = Query(True, description="Only show active customers")
):
    """List all customers (admin only)."""
    customers = api_key_manager.list_customers(active_only=active_only)
    
    return [
        CustomerResponse(
            id=c.id,
            name=c.name,
            tier=c.tier,
            active=c.active,
            created_at=c.created_at.isoformat(),
            max_api_keys=c.max_api_keys,
            max_contracts=c.max_contracts,
            max_chains=c.max_chains,
            features=list(c.features),
            admin_email=c.admin_email,
            contracts_count=len(c.contracts)
        )
        for c in customers
    ]


@router.get("/{customer_id}", response_model=CustomerResponse)
async def get_customer(customer_id: str):
    """Get customer details."""
    customer = api_key_manager.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    return CustomerResponse(
        id=customer.id,
        name=customer.name,
        tier=customer.tier,
        active=customer.active,
        created_at=customer.created_at.isoformat(),
        max_api_keys=customer.max_api_keys,
        max_contracts=customer.max_contracts,
        max_chains=customer.max_chains,
        features=list(customer.features),
        admin_email=customer.admin_email,
        contracts_count=len(customer.contracts)
    )


@router.patch("/{customer_id}")
async def update_customer(
    customer_id: str,
    updates: Dict[str, Any] = Body(...)
):
    """Update customer details."""
    customer = api_key_manager.update_customer(customer_id, **updates)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    return {"status": "updated", "customer_id": customer_id}


@router.delete("/{customer_id}")
async def deactivate_customer(customer_id: str):
    """Deactivate a customer (soft delete)."""
    customer = api_key_manager.update_customer(customer_id, active=False)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    return {"status": "deactivated", "customer_id": customer_id}


# =============================================================================
# API Key Management Endpoints
# =============================================================================

@router.post("/{customer_id}/api-keys", response_model=APIKeyCreatedResponse)
async def generate_api_key(
    customer_id: str,
    request: GenerateAPIKeyRequest
):
    """
    Generate a new API key for a customer.
    
    ⚠️ IMPORTANT: The API key is only shown ONCE in this response!
    Store it securely - we cannot retrieve it later.
    """
    try:
        # Convert scope strings to enums
        scopes = set()
        for scope_str in request.scopes:
            try:
                scopes.add(KeyScope(scope_str))
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid scope: {scope_str}. Valid: read, write, admin, guardian"
                )
        
        raw_key, api_key = api_key_manager.generate_api_key(
            customer_id=customer_id,
            name=request.name,
            scopes=scopes,
            expires_in_days=request.expires_in_days,
            description=request.description,
            allowed_ips=request.allowed_ips
        )
        
        return APIKeyCreatedResponse(
            api_key=raw_key,
            key_details=APIKeyResponse(
                id=api_key.id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                scopes=[s.value for s in api_key.scopes],
                status=api_key.status.value,
                created_at=api_key.created_at.isoformat(),
                expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
                last_used_at=None,
                total_requests=0,
                rate_limit=api_key.rate_limit_requests
            )
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{customer_id}/api-keys", response_model=List[APIKeyResponse])
async def list_api_keys(customer_id: str):
    """List all API keys for a customer (keys are masked)."""
    customer = api_key_manager.get_customer(customer_id)
    if not customer:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    keys = api_key_manager.get_customer_keys(customer_id)
    
    return [
        APIKeyResponse(
            id=k.id,
            name=k.name,
            key_prefix=k.key_prefix,
            scopes=[s.value for s in k.scopes],
            status=k.status.value,
            created_at=k.created_at.isoformat(),
            expires_at=k.expires_at.isoformat() if k.expires_at else None,
            last_used_at=k.last_used_at.isoformat() if k.last_used_at else None,
            total_requests=k.total_requests,
            rate_limit=k.rate_limit_requests
        )
        for k in keys
    ]


@router.post("/{customer_id}/api-keys/{key_id}/rotate", response_model=APIKeyCreatedResponse)
async def rotate_api_key(customer_id: str, key_id: str):
    """
    Rotate an API key (revoke old, generate new).
    
    ⚠️ The old key will stop working immediately!
    """
    raw_key, api_key = api_key_manager.rotate_key(key_id)
    
    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return APIKeyCreatedResponse(
        api_key=raw_key,
        key_details=APIKeyResponse(
            id=api_key.id,
            name=api_key.name,
            key_prefix=api_key.key_prefix,
            scopes=[s.value for s in api_key.scopes],
            status=api_key.status.value,
            created_at=api_key.created_at.isoformat(),
            expires_at=api_key.expires_at.isoformat() if api_key.expires_at else None,
            last_used_at=None,
            total_requests=0,
            rate_limit=api_key.rate_limit_requests
        )
    )


@router.delete("/{customer_id}/api-keys/{key_id}")
async def revoke_api_key(customer_id: str, key_id: str):
    """Revoke an API key. Cannot be undone."""
    success = api_key_manager.revoke_key(key_id)
    
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return {"status": "revoked", "key_id": key_id}


@router.get("/{customer_id}/api-keys/{key_id}/usage")
async def get_api_key_usage(customer_id: str, key_id: str):
    """Get usage statistics for an API key."""
    stats = api_key_manager.get_key_usage_stats(key_id)
    
    if not stats:
        raise HTTPException(status_code=404, detail="API key not found")
    
    return stats


# =============================================================================
# Contract Management Endpoints
# =============================================================================

@router.post("/{customer_id}/contracts", response_model=ContractResponse)
async def add_contract(customer_id: str, request: AddContractRequest):
    """
    Add a contract for monitoring.
    
    Contracts will be monitored for:
    - Bridge protocols: cross-chain events, TVL changes
    - DeFi protocols: flash loans, liquidations, admin actions
    - Tokens: large transfers, suspicious activity
    """
    try:
        success = api_key_manager.add_customer_contract(
            customer_id=customer_id,
            chain_id=request.chain_id,
            contract_address=request.contract_address,
            contract_type=request.contract_type,
            contract_name=request.contract_name,
            metadata=request.metadata
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Customer not found")
        
        return ContractResponse(
            chain_id=request.chain_id,
            address=request.contract_address.lower(),
            type=request.contract_type,
            name=request.contract_name,
            added_at=datetime.now(timezone.utc).isoformat()
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/{customer_id}/contracts", response_model=List[ContractResponse])
async def list_contracts(customer_id: str):
    """List all contracts monitored for a customer."""
    contracts = api_key_manager.get_customer_contracts(customer_id)
    
    if contracts is None:
        raise HTTPException(status_code=404, detail="Customer not found")
    
    return [
        ContractResponse(
            chain_id=c["chain_id"],
            address=c["address"],
            type=c["type"],
            name=c["name"],
            added_at=c["added_at"]
        )
        for c in contracts
    ]


@router.delete("/{customer_id}/contracts/{chain_id}/{contract_address}")
async def remove_contract(customer_id: str, chain_id: str, contract_address: str):
    """Remove a contract from monitoring."""
    success = api_key_manager.remove_customer_contract(
        customer_id=customer_id,
        chain_id=chain_id,
        contract_address=contract_address
    )
    
    if not success:
        raise HTTPException(status_code=404, detail="Customer or contract not found")
    
    return {"status": "removed", "contract": contract_address}


# =============================================================================
# Statistics Endpoints
# =============================================================================

@router.get("/stats/overview")
async def get_customer_stats():
    """Get overall customer and API key statistics."""
    return api_key_manager.get_stats()


# =============================================================================
# Self-Service Onboarding Flow
# =============================================================================

class OnboardingRequest(BaseModel):
    """Complete onboarding request."""
    # Customer info
    organization_name: str
    admin_email: str
    tier: str = "starter"
    
    # Initial contracts
    contracts: List[AddContractRequest] = []
    
    # Alert settings
    telegram_chat_id: Optional[str] = None
    slack_webhook: Optional[str] = None
    alert_emails: List[str] = []


class OnboardingResponse(BaseModel):
    """Complete onboarding response."""
    customer: CustomerResponse
    api_key: str  # Shown once!
    key_details: APIKeyResponse
    contracts_added: int
    next_steps: List[str]


@router.post("/onboard", response_model=OnboardingResponse)
async def complete_onboarding(request: OnboardingRequest):
    """
    Complete customer onboarding in one step.
    
    Creates:
    1. Customer account
    2. Initial API key with read/write access
    3. Adds provided contracts for monitoring
    
    Returns the API key (SHOW ONCE!) and next steps.
    """
    try:
        # 1. Create customer
        customer = api_key_manager.create_customer(
            name=request.organization_name,
            tier=request.tier,
            admin_email=request.admin_email,
            alert_emails=request.alert_emails,
            telegram_chat_id=request.telegram_chat_id,
            slack_webhook=request.slack_webhook
        )
        
        # 2. Generate initial API key
        raw_key, api_key = api_key_manager.generate_api_key(
            customer_id=customer.id,
            name="Primary API Key",
            scopes={KeyScope.READ, KeyScope.WRITE},
            description="Auto-generated during onboarding"
        )
        
        # 3. Add contracts
        contracts_added = 0
        for contract in request.contracts:
            try:
                api_key_manager.add_customer_contract(
                    customer_id=customer.id,
                    chain_id=contract.chain_id,
                    contract_address=contract.contract_address,
                    contract_type=contract.contract_type,
                    contract_name=contract.contract_name,
                    metadata=contract.metadata
                )
                contracts_added += 1
            except ValueError:
                pass  # Skip if limit reached
        
        # 4. Generate next steps
        next_steps = [
            "🔑 Store your API key securely - it won't be shown again!",
            f"📊 View your dashboard at /dashboard?customer={customer.id}",
            "📋 Add more contracts in Settings > Contracts",
        ]
        
        if not request.telegram_chat_id and not request.slack_webhook:
            next_steps.append("🔔 Configure alerting in Settings > Alerts")
        
        if request.tier == "starter":
            next_steps.append("⬆️ Upgrade to Growth tier for Guardian auto-pause feature")
        
        logger.info(
            "customer_onboarded",
            customer_id=customer.id,
            name=customer.name,
            tier=customer.tier,
            contracts=contracts_added
        )
        
        return OnboardingResponse(
            customer=CustomerResponse(
                id=customer.id,
                name=customer.name,
                tier=customer.tier,
                active=customer.active,
                created_at=customer.created_at.isoformat(),
                max_api_keys=customer.max_api_keys,
                max_contracts=customer.max_contracts,
                max_chains=customer.max_chains,
                features=list(customer.features),
                admin_email=customer.admin_email,
                contracts_count=contracts_added
            ),
            api_key=raw_key,
            key_details=APIKeyResponse(
                id=api_key.id,
                name=api_key.name,
                key_prefix=api_key.key_prefix,
                scopes=[s.value for s in api_key.scopes],
                status=api_key.status.value,
                created_at=api_key.created_at.isoformat(),
                expires_at=None,
                last_used_at=None,
                total_requests=0,
                rate_limit=api_key.rate_limit_requests
            ),
            contracts_added=contracts_added,
            next_steps=next_steps
        )
        
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

