"""
Security Utilities for Sentinel3
Input validation, sanitization, and security helpers
"""

import re
import html
from typing import Optional, Any
import structlog

logger = structlog.get_logger(__name__)

# ============================================================================
# Input Validation
# ============================================================================

# Valid patterns for common inputs
PATTERNS = {
    "chain_id": re.compile(r"^[a-z0-9_-]{1,50}$"),
    "event_type": re.compile(r"^[a-zA-Z0-9_-]{1,100}$"),
    "severity": re.compile(r"^(LOW|MEDIUM|HIGH|CRITICAL|INFO)$", re.IGNORECASE),
    "status": re.compile(r"^(OPEN|OPEN_PENDING|ACKNOWLEDGED|RESOLVED|CLOSED)$", re.IGNORECASE),
    "address": re.compile(r"^0x[a-fA-F0-9]{40}$"),
    "tx_hash": re.compile(r"^0x[a-fA-F0-9]{64}$"),
    "uuid": re.compile(r"^[a-fA-F0-9-]{36}$"),
    "incident_id": re.compile(r"^[a-zA-Z0-9_-]{1,200}$"),
}


def validate_chain_id(value: Optional[str]) -> Optional[str]:
    """Validate and sanitize chain_id input"""
    if value is None:
        return None
    value = str(value).strip().lower()
    if not PATTERNS["chain_id"].match(value):
        logger.warning("invalid_chain_id", value=value[:20])
        return None
    return value


def validate_event_type(value: Optional[str]) -> Optional[str]:
    """Validate and sanitize event_type input"""
    if value is None:
        return None
    value = str(value).strip()
    if not PATTERNS["event_type"].match(value):
        logger.warning("invalid_event_type", value=value[:20])
        return None
    return value


def validate_severity(value: Optional[str]) -> Optional[str]:
    """Validate and sanitize severity input"""
    if value is None:
        return None
    value = str(value).strip().upper()
    if not PATTERNS["severity"].match(value):
        logger.warning("invalid_severity", value=value[:20])
        return None
    return value


def validate_status(value: Optional[str]) -> Optional[str]:
    """Validate and sanitize status input"""
    if value is None:
        return None
    value = str(value).strip().upper()
    if not PATTERNS["status"].match(value):
        logger.warning("invalid_status", value=value[:20])
        return None
    return value


def validate_address(value: Optional[str]) -> Optional[str]:
    """Validate Ethereum/EVM address"""
    if value is None:
        return None
    value = str(value).strip().lower()
    if not PATTERNS["address"].match(value):
        logger.warning("invalid_address", value=value[:20])
        return None
    return value


def validate_tx_hash(value: Optional[str]) -> Optional[str]:
    """Validate transaction hash"""
    if value is None:
        return None
    value = str(value).strip().lower()
    if not PATTERNS["tx_hash"].match(value):
        logger.warning("invalid_tx_hash", value=value[:20])
        return None
    return value


def validate_incident_id(value: Optional[str]) -> Optional[str]:
    """Validate incident ID"""
    if value is None:
        return None
    value = str(value).strip()
    if not PATTERNS["incident_id"].match(value):
        logger.warning("invalid_incident_id", value=value[:50])
        return None
    return value


def validate_limit(value: Any, max_limit: int = 1000, default: int = 100) -> int:
    """Validate and constrain limit parameter"""
    try:
        limit = int(value)
        if limit < 1:
            return default
        if limit > max_limit:
            return max_limit
        return limit
    except (ValueError, TypeError):
        return default


def validate_offset(value: Any, max_offset: int = 100000, default: int = 0) -> int:
    """Validate and constrain offset parameter"""
    try:
        offset = int(value)
        if offset < 0:
            return default
        if offset > max_offset:
            return max_offset
        return offset
    except (ValueError, TypeError):
        return default


# ============================================================================
# Sanitization
# ============================================================================

def sanitize_string(value: Optional[str], max_length: int = 1000) -> Optional[str]:
    """Sanitize string input - remove dangerous characters"""
    if value is None:
        return None
    
    # Truncate
    value = str(value)[:max_length]
    
    # Remove null bytes and other control characters
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)
    
    return value.strip()


def sanitize_html(value: Optional[str]) -> Optional[str]:
    """Escape HTML to prevent XSS"""
    if value is None:
        return None
    return html.escape(str(value))


def sanitize_for_log(value: Any, max_length: int = 200) -> str:
    """Sanitize value for safe logging"""
    if value is None:
        return "None"
    
    str_value = str(value)[:max_length]
    
    # Remove newlines and control characters
    str_value = re.sub(r'[\n\r\t]', ' ', str_value)
    str_value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', str_value)
    
    return str_value


# ============================================================================
# SQL Safety
# ============================================================================

# Allowed column names for dynamic queries (whitelist approach)
ALLOWED_EVENT_COLUMNS = frozenset([
    "id", "event_id", "chain_id", "event_type", "tx_hash", "block_number",
    "block_timestamp", "contract_address", "severity", "amount", "amount_usd",
    "from_address", "to_address", "raw_data", "created_at", "status"
])

ALLOWED_INCIDENT_COLUMNS = frozenset([
    "id", "incident_id", "title", "summary", "severity", "status", "confidence",
    "attack_type", "total_loss_usd", "affected_chains", "created_at", "updated_at"
])

ALLOWED_ORDER_DIRECTIONS = frozenset(["ASC", "DESC"])


def validate_column_name(column: str, allowed: frozenset) -> Optional[str]:
    """Validate column name against whitelist"""
    column = str(column).strip().lower()
    if column in allowed:
        return column
    logger.warning("invalid_column_name", column=column[:50])
    return None


def validate_order_direction(direction: str) -> str:
    """Validate ORDER BY direction"""
    direction = str(direction).strip().upper()
    if direction in ALLOWED_ORDER_DIRECTIONS:
        return direction
    return "DESC"


# ============================================================================
# Rate Limit Helpers
# ============================================================================

def get_client_ip(request) -> str:
    """Extract client IP from request, handling proxies"""
    # Check X-Forwarded-For header (load balancer/proxy)
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        # Take first IP (original client)
        return forwarded.split(",")[0].strip()
    
    # Check X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    
    # Fall back to direct client
    if request.client:
        return request.client.host
    
    return "unknown"


# ============================================================================
# Sensitive Data Masking
# ============================================================================

def mask_address(address: Optional[str]) -> str:
    """Mask an address for logging (show first 6 and last 4 chars)"""
    if not address:
        return "N/A"
    if len(address) < 12:
        return "***"
    return f"{address[:6]}...{address[-4:]}"


def mask_private_key(key: Optional[str]) -> str:
    """Completely mask private keys"""
    if not key:
        return "N/A"
    return "***REDACTED***"


def mask_api_key(key: Optional[str]) -> str:
    """Mask API key for logging (show first 4 chars only)"""
    if not key:
        return "N/A"
    if len(key) < 8:
        return "***"
    return f"{key[:4]}...***"
