"""
API Key Management System
=========================

Secure API key generation, validation, and management for Sentinel3 customers.

Features:
1. API key generation with secure random tokens
2. Key rotation and revocation
3. Rate limiting per key
4. Usage tracking and analytics
5. Scoped permissions (read, write, admin)
6. Customer isolation
"""

import hashlib
import secrets
import structlog
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set
from enum import Enum
import asyncio

logger = structlog.get_logger(__name__)


class KeyScope(Enum):
    """API key permission scopes."""
    READ = "read"           # View events, incidents, stats
    WRITE = "write"         # Create alerts, update incidents
    ADMIN = "admin"         # Manage team, settings
    GUARDIAN = "guardian"   # Execute pause operations


class KeyStatus(Enum):
    """API key status."""
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    RATE_LIMITED = "rate_limited"


@dataclass
class APIKey:
    """API Key record."""
    id: str
    customer_id: str
    name: str
    
    # The actual key (hashed after creation)
    key_hash: str
    key_prefix: str  # First 8 chars for identification (s3_abc123...)
    
    # Permissions
    scopes: Set[KeyScope]
    
    # Status
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    revoked_at: Optional[datetime] = None
    
    # Rate limiting
    rate_limit_requests: int = 1000  # Requests per hour
    rate_limit_window: int = 3600    # Window in seconds
    
    # Usage tracking
    total_requests: int = 0
    requests_this_window: int = 0
    window_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Metadata
    created_by: Optional[str] = None
    description: str = ""
    allowed_ips: List[str] = field(default_factory=list)  # Empty = all allowed


@dataclass
class Customer:
    """Customer/Organization record."""
    id: str
    name: str
    tier: str  # starter, growth, enterprise
    
    # Status
    active: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Limits based on tier
    max_api_keys: int = 5
    max_contracts: int = 10
    max_chains: int = 3
    rate_limit_multiplier: float = 1.0
    
    # Features
    features: Set[str] = field(default_factory=lambda: {"events", "incidents", "alerts"})
    
    # Contacts
    admin_email: str = ""
    alert_emails: List[str] = field(default_factory=list)
    telegram_chat_id: Optional[str] = None
    slack_webhook: Optional[str] = None
    
    # Contracts being monitored
    contracts: List[Dict] = field(default_factory=list)


class APIKeyManager:
    """
    Manages API keys for customers.
    
    Usage:
        manager = APIKeyManager()
        
        # Create customer
        customer = manager.create_customer("Aave", "enterprise")
        
        # Generate API key
        key, api_key = manager.generate_api_key(
            customer_id=customer.id,
            name="Production Key",
            scopes={KeyScope.READ, KeyScope.WRITE}
        )
        
        # Validate on request
        if manager.validate_key(key):
            # Allow access
            pass
    """
    
    # Tier configurations
    TIER_CONFIGS = {
        "starter": {
            "max_api_keys": 2,
            "max_contracts": 5,
            "max_chains": 2,
            "rate_limit": 500,
            "rate_limit_multiplier": 1.0,
            "features": {"events", "incidents", "alerts"},
        },
        "growth": {
            "max_api_keys": 5,
            "max_contracts": 20,
            "max_chains": 5,
            "rate_limit": 2000,
            "rate_limit_multiplier": 2.0,
            "features": {"events", "incidents", "alerts", "analytics", "guardian"},
        },
        "enterprise": {
            "max_api_keys": 20,
            "max_contracts": 100,
            "max_chains": 20,
            "rate_limit": 10000,
            "rate_limit_multiplier": 10.0,
            "features": {"events", "incidents", "alerts", "analytics", "guardian", "ml_analysis", "custom_rules"},
        },
    }
    
    def __init__(self):
        self.customers: Dict[str, Customer] = {}
        self.api_keys: Dict[str, APIKey] = {}  # key_hash -> APIKey
        self.key_prefix_map: Dict[str, str] = {}  # prefix -> key_hash
        
        # Rate limiting cache
        self._rate_limit_cache: Dict[str, List[datetime]] = {}
        
        # Statistics
        self._stats = {
            "total_validations": 0,
            "successful_validations": 0,
            "failed_validations": 0,
            "rate_limited_requests": 0,
        }
    
    # =========================================================================
    # Customer Management
    # =========================================================================
    
    def create_customer(
        self,
        name: str,
        tier: str = "starter",
        admin_email: str = "",
        **kwargs
    ) -> Customer:
        """Create a new customer."""
        if tier not in self.TIER_CONFIGS:
            raise ValueError(f"Invalid tier: {tier}. Must be one of {list(self.TIER_CONFIGS.keys())}")
        
        config = self.TIER_CONFIGS[tier]
        
        customer_id = f"cust_{secrets.token_hex(8)}"
        
        customer = Customer(
            id=customer_id,
            name=name,
            tier=tier,
            max_api_keys=config["max_api_keys"],
            max_contracts=config["max_contracts"],
            max_chains=config["max_chains"],
            rate_limit_multiplier=config["rate_limit_multiplier"],
            features=config["features"],
            admin_email=admin_email,
            **kwargs
        )
        
        self.customers[customer_id] = customer
        
        logger.info(
            "customer_created",
            customer_id=customer_id,
            name=name,
            tier=tier
        )
        
        return customer
    
    def get_customer(self, customer_id: str) -> Optional[Customer]:
        """Get customer by ID."""
        return self.customers.get(customer_id)
    
    def update_customer(self, customer_id: str, **updates) -> Optional[Customer]:
        """Update customer fields."""
        customer = self.customers.get(customer_id)
        if not customer:
            return None
        
        for key, value in updates.items():
            if hasattr(customer, key):
                setattr(customer, key, value)
        
        return customer
    
    def list_customers(self, active_only: bool = True) -> List[Customer]:
        """List all customers."""
        customers = list(self.customers.values())
        if active_only:
            customers = [c for c in customers if c.active]
        return customers
    
    # =========================================================================
    # API Key Management
    # =========================================================================
    
    def generate_api_key(
        self,
        customer_id: str,
        name: str,
        scopes: Set[KeyScope],
        expires_in_days: Optional[int] = None,
        description: str = "",
        allowed_ips: Optional[List[str]] = None,
        created_by: Optional[str] = None
    ) -> tuple[str, APIKey]:
        """
        Generate a new API key for a customer.
        
        Returns:
            tuple: (raw_key, APIKey object)
            
        The raw_key should be shown to user ONCE and never stored.
        We only store the hash.
        """
        customer = self.customers.get(customer_id)
        if not customer:
            raise ValueError(f"Customer not found: {customer_id}")
        
        # Check key limit
        customer_keys = [k for k in self.api_keys.values() if k.customer_id == customer_id]
        if len(customer_keys) >= customer.max_api_keys:
            raise ValueError(f"Customer has reached API key limit ({customer.max_api_keys})")
        
        # Generate secure key
        # Format: s3_<customer_prefix>_<random>
        raw_key = f"s3_{customer_id[:8]}_{secrets.token_urlsafe(32)}"
        key_prefix = raw_key[:16]
        key_hash = self._hash_key(raw_key)
        
        # Calculate expiration
        expires_at = None
        if expires_in_days:
            expires_at = datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        
        # Get rate limit from tier
        tier_config = self.TIER_CONFIGS.get(customer.tier, self.TIER_CONFIGS["starter"])
        rate_limit = int(tier_config["rate_limit"] * customer.rate_limit_multiplier)
        
        # Create API key record
        api_key = APIKey(
            id=f"key_{secrets.token_hex(8)}",
            customer_id=customer_id,
            name=name,
            key_hash=key_hash,
            key_prefix=key_prefix,
            scopes=scopes,
            expires_at=expires_at,
            rate_limit_requests=rate_limit,
            description=description,
            allowed_ips=allowed_ips or [],
            created_by=created_by
        )
        
        # Store
        self.api_keys[key_hash] = api_key
        self.key_prefix_map[key_prefix] = key_hash
        
        logger.info(
            "api_key_generated",
            key_id=api_key.id,
            customer_id=customer_id,
            key_prefix=key_prefix,
            scopes=[s.value for s in scopes]
        )
        
        return raw_key, api_key
    
    def validate_key(
        self,
        raw_key: str,
        required_scope: Optional[KeyScope] = None,
        client_ip: Optional[str] = None
    ) -> tuple[bool, Optional[APIKey], str]:
        """
        Validate an API key.
        
        Returns:
            tuple: (is_valid, api_key, error_message)
        """
        self._stats["total_validations"] += 1
        
        # Check format
        if not raw_key or not raw_key.startswith("s3_"):
            self._stats["failed_validations"] += 1
            return False, None, "Invalid key format"
        
        # Hash and lookup
        key_hash = self._hash_key(raw_key)
        api_key = self.api_keys.get(key_hash)
        
        if not api_key:
            self._stats["failed_validations"] += 1
            return False, None, "Invalid API key"
        
        # Check status
        if api_key.status == KeyStatus.REVOKED:
            self._stats["failed_validations"] += 1
            return False, api_key, "API key has been revoked"
        
        # Check expiration
        if api_key.expires_at and datetime.now(timezone.utc) > api_key.expires_at:
            api_key.status = KeyStatus.EXPIRED
            self._stats["failed_validations"] += 1
            return False, api_key, "API key has expired"
        
        # Check customer is active
        customer = self.customers.get(api_key.customer_id)
        if not customer or not customer.active:
            self._stats["failed_validations"] += 1
            return False, api_key, "Customer account is inactive"
        
        # Check IP allowlist
        if api_key.allowed_ips and client_ip:
            if client_ip not in api_key.allowed_ips:
                self._stats["failed_validations"] += 1
                return False, api_key, f"IP {client_ip} not allowed"
        
        # Check scope
        if required_scope and required_scope not in api_key.scopes:
            self._stats["failed_validations"] += 1
            return False, api_key, f"Missing required scope: {required_scope.value}"
        
        # Check rate limit
        if not self._check_rate_limit(api_key):
            self._stats["rate_limited_requests"] += 1
            return False, api_key, "Rate limit exceeded"
        
        # Update usage
        api_key.last_used_at = datetime.now(timezone.utc)
        api_key.total_requests += 1
        api_key.requests_this_window += 1
        
        self._stats["successful_validations"] += 1
        return True, api_key, ""
    
    def _check_rate_limit(self, api_key: APIKey) -> bool:
        """Check if request is within rate limit."""
        now = datetime.now(timezone.utc)
        
        # Reset window if expired
        window_age = (now - api_key.window_start).total_seconds()
        if window_age > api_key.rate_limit_window:
            api_key.window_start = now
            api_key.requests_this_window = 0
        
        # Check limit
        if api_key.requests_this_window >= api_key.rate_limit_requests:
            return False
        
        return True
    
    def revoke_key(self, key_id: str, revoked_by: Optional[str] = None) -> bool:
        """Revoke an API key."""
        for api_key in self.api_keys.values():
            if api_key.id == key_id:
                api_key.status = KeyStatus.REVOKED
                api_key.revoked_at = datetime.now(timezone.utc)
                
                logger.warning(
                    "api_key_revoked",
                    key_id=key_id,
                    revoked_by=revoked_by
                )
                return True
        return False
    
    def rotate_key(
        self,
        key_id: str,
        rotated_by: Optional[str] = None
    ) -> tuple[Optional[str], Optional[APIKey]]:
        """
        Rotate an API key (revoke old, generate new).
        
        Returns:
            tuple: (new_raw_key, new_api_key) or (None, None)
        """
        # Find old key
        old_key = None
        for api_key in self.api_keys.values():
            if api_key.id == key_id:
                old_key = api_key
                break
        
        if not old_key:
            return None, None
        
        # Generate new key with same settings
        new_raw_key, new_api_key = self.generate_api_key(
            customer_id=old_key.customer_id,
            name=f"{old_key.name} (rotated)",
            scopes=old_key.scopes,
            description=f"Rotated from {old_key.id}",
            allowed_ips=old_key.allowed_ips,
            created_by=rotated_by
        )
        
        # Revoke old key
        self.revoke_key(key_id, revoked_by=rotated_by)
        
        logger.info(
            "api_key_rotated",
            old_key_id=key_id,
            new_key_id=new_api_key.id,
            rotated_by=rotated_by
        )
        
        return new_raw_key, new_api_key
    
    def get_customer_keys(self, customer_id: str) -> List[APIKey]:
        """Get all API keys for a customer."""
        return [k for k in self.api_keys.values() if k.customer_id == customer_id]
    
    def _hash_key(self, raw_key: str) -> str:
        """Hash an API key for storage."""
        return hashlib.sha256(raw_key.encode()).hexdigest()
    
    # =========================================================================
    # Contract Management
    # =========================================================================
    
    def add_customer_contract(
        self,
        customer_id: str,
        chain_id: str,
        contract_address: str,
        contract_type: str = "defi",  # defi, bridge, token
        contract_name: str = "",
        metadata: Optional[Dict] = None
    ) -> bool:
        """Add a contract to monitor for a customer."""
        customer = self.customers.get(customer_id)
        if not customer:
            return False
        
        # Check contract limit
        if len(customer.contracts) >= customer.max_contracts:
            raise ValueError(f"Customer has reached contract limit ({customer.max_contracts})")
        
        # Check chain limit
        chains = {c["chain_id"] for c in customer.contracts}
        chains.add(chain_id)
        if len(chains) > customer.max_chains:
            raise ValueError(f"Customer has reached chain limit ({customer.max_chains})")
        
        # Add contract
        contract = {
            "chain_id": chain_id,
            "address": contract_address.lower(),
            "type": contract_type,
            "name": contract_name,
            "added_at": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata or {}
        }
        
        customer.contracts.append(contract)
        
        logger.info(
            "customer_contract_added",
            customer_id=customer_id,
            chain_id=chain_id,
            contract=contract_address
        )
        
        return True
    
    def remove_customer_contract(
        self,
        customer_id: str,
        chain_id: str,
        contract_address: str
    ) -> bool:
        """Remove a contract from customer's monitoring list."""
        customer = self.customers.get(customer_id)
        if not customer:
            return False
        
        address = contract_address.lower()
        customer.contracts = [
            c for c in customer.contracts
            if not (c["chain_id"] == chain_id and c["address"] == address)
        ]
        
        return True
    
    def get_customer_contracts(self, customer_id: str) -> List[Dict]:
        """Get all contracts monitored for a customer."""
        customer = self.customers.get(customer_id)
        if not customer:
            return []
        return customer.contracts
    
    # =========================================================================
    # Statistics
    # =========================================================================
    
    def get_stats(self) -> Dict:
        """Get API key manager statistics."""
        return {
            **self._stats,
            "total_customers": len(self.customers),
            "active_customers": len([c for c in self.customers.values() if c.active]),
            "total_api_keys": len(self.api_keys),
            "active_api_keys": len([k for k in self.api_keys.values() if k.status == KeyStatus.ACTIVE]),
            "revoked_api_keys": len([k for k in self.api_keys.values() if k.status == KeyStatus.REVOKED]),
        }
    
    def get_key_usage_stats(self, key_id: str) -> Optional[Dict]:
        """Get usage statistics for a specific API key."""
        for api_key in self.api_keys.values():
            if api_key.id == key_id:
                return {
                    "key_id": api_key.id,
                    "customer_id": api_key.customer_id,
                    "total_requests": api_key.total_requests,
                    "requests_this_window": api_key.requests_this_window,
                    "rate_limit": api_key.rate_limit_requests,
                    "last_used": api_key.last_used_at.isoformat() if api_key.last_used_at else None,
                    "created_at": api_key.created_at.isoformat(),
                    "status": api_key.status.value,
                }
        return None


# Global instance
api_key_manager = APIKeyManager()


# =============================================================================
# FastAPI Integration
# =============================================================================

from fastapi import HTTPException, Header, Depends
from typing import Annotated


async def verify_api_key(
    x_api_key: Annotated[str, Header()] = None,
    authorization: Annotated[str, Header()] = None
) -> APIKey:
    """
    FastAPI dependency to verify API key.
    
    Usage:
        @app.get("/api/events")
        async def get_events(api_key: APIKey = Depends(verify_api_key)):
            # api_key is validated
            pass
    """
    # Get key from header
    raw_key = x_api_key
    if not raw_key and authorization:
        # Support Bearer token format
        if authorization.startswith("Bearer "):
            raw_key = authorization[7:]
    
    if not raw_key:
        raise HTTPException(
            status_code=401,
            detail="API key required. Provide X-API-Key header or Authorization: Bearer <key>"
        )
    
    is_valid, api_key, error = api_key_manager.validate_key(raw_key)
    
    if not is_valid:
        raise HTTPException(
            status_code=401 if "Invalid" in error else 403,
            detail=error
        )
    
    return api_key


def require_scope(scope: KeyScope):
    """
    FastAPI dependency factory for scope requirements.
    
    Usage:
        @app.post("/api/incidents/{id}/acknowledge")
        async def acknowledge(
            id: str,
            api_key: APIKey = Depends(require_scope(KeyScope.WRITE))
        ):
            pass
    """
    async def _check_scope(api_key: APIKey = Depends(verify_api_key)) -> APIKey:
        if scope not in api_key.scopes:
            raise HTTPException(
                status_code=403,
                detail=f"This endpoint requires '{scope.value}' scope"
            )
        return api_key
    
    return _check_scope


def require_feature(feature: str):
    """
    FastAPI dependency factory for feature requirements.
    
    Usage:
        @app.get("/api/analytics")
        async def get_analytics(
            api_key: APIKey = Depends(require_feature("analytics"))
        ):
            pass
    """
    async def _check_feature(api_key: APIKey = Depends(verify_api_key)) -> APIKey:
        customer = api_key_manager.get_customer(api_key.customer_id)
        if not customer or feature not in customer.features:
            raise HTTPException(
                status_code=403,
                detail=f"This feature '{feature}' is not available on your plan"
            )
        return api_key
    
    return _check_feature

