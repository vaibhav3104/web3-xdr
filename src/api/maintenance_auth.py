"""
Maintenance Endpoint Authentication and Authorization
"""

import os
from typing import Optional
from fastapi import HTTPException, Header, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import structlog

from ..auth.jwt_handler import JWTHandler
from ..database.models import AuditLogModel
from ..database.connection import DatabaseManager
from sqlalchemy import select
from datetime import datetime, timezone

logger = structlog.get_logger(__name__)

# Environment variables
ENABLE_MAINTENANCE_ENDPOINTS = os.getenv("ENABLE_MAINTENANCE_ENDPOINTS", "false").lower() == "true"
MAINTENANCE_TOKEN = os.getenv("MAINTENANCE_TOKEN", "")

security = HTTPBearer()


async def require_maintenance_access(
    authorization: Optional[HTTPAuthorizationCredentials] = Security(security),
    x_maintenance_token: Optional[str] = Header(None, alias="X-Maintenance-Token")
) -> dict:
    """
    Require maintenance access via:
    1. JWT token with admin role, OR
    2. MAINTENANCE_TOKEN header
    
    Returns user info for audit logging.
    """
    if not ENABLE_MAINTENANCE_ENDPOINTS:
        logger.warning("maintenance_endpoints_disabled")
        raise HTTPException(
            status_code=403,
            detail="Maintenance endpoints are disabled. Set ENABLE_MAINTENANCE_ENDPOINTS=true"
        )
    
    user_info = {
        "user": "unknown",
        "method": "unknown",
        "authenticated": False
    }
    
    # Check MAINTENANCE_TOKEN header (preferred for automation)
    if x_maintenance_token:
        if not MAINTENANCE_TOKEN:
            logger.warning("maintenance_token_not_configured")
            raise HTTPException(
                status_code=500,
                detail="MAINTENANCE_TOKEN not configured in environment"
            )
        
        if x_maintenance_token != MAINTENANCE_TOKEN:
            logger.warning("invalid_maintenance_token", token_prefix=x_maintenance_token[:8] if x_maintenance_token else None)
            raise HTTPException(
                status_code=401,
                detail="Invalid maintenance token"
            )
        
        user_info.update({
            "user": "maintenance_token",
            "method": "token",
            "authenticated": True
        })
        return user_info
    
    # Check JWT token with admin role
    if authorization:
        try:
            jwt_handler = JWTHandler()
            payload = jwt_handler.verify_token(authorization.credentials)
            
            # Check for admin role
            user_roles = payload.get("roles", [])
            if "admin" not in user_roles:
                logger.warning("insufficient_permissions", user=payload.get("sub"), roles=user_roles)
                raise HTTPException(
                    status_code=403,
                    detail="Admin role required for maintenance endpoints"
                )
            
            user_info.update({
                "user": payload.get("sub", "unknown"),
                "method": "jwt",
                "authenticated": True,
                "roles": user_roles
            })
            return user_info
            
        except Exception as e:
            logger.warning("jwt_verification_failed", error=str(e))
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired token"
            )
    
    # No valid authentication
    logger.warning("maintenance_access_denied_no_auth")
    raise HTTPException(
        status_code=401,
        detail="Authentication required. Provide X-Maintenance-Token header or valid JWT with admin role"
    )


async def log_maintenance_action(
    action_type: str,
    user_info: dict,
    payload: dict,
    outcome: str = "success",
    error_message: Optional[str] = None
):
    """
    Log maintenance action to audit_logs table.
    """
    try:
        async with DatabaseManager.get_session() as session:
            import json
            details = payload.copy()
            if error_message:
                details["error"] = error_message
            details["outcome"] = outcome
            
            audit_log = AuditLogModel(
                action_type=action_type,
                actor_id=user_info.get("user", "unknown"),
                resource_id=None,
                details=details,
                ip_address=None,  # Could extract from request if needed
                # Legacy fields for backward compatibility
                action=action_type,
                entity_type="maintenance",
                entity_id=None,
                user=user_info.get("user", "unknown")
            )
            session.add(audit_log)
            await session.commit()
            logger.info("maintenance_action_logged", action=action_type, user=user_info.get("user"), outcome=outcome)
    except Exception as e:
        logger.error("audit_log_failed", error=str(e))
        # Don't fail the request if audit logging fails
