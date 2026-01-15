"""
Audit Logging System
====================

Phase 5: Comprehensive audit logging for all system actions.
Tracks who did what, when, and why.
"""

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from enum import Enum
import structlog

from .models import AuditLogModel
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from contextlib import contextmanager
import os

logger = structlog.get_logger(__name__)


class ActionType(Enum):
    """Types of actions to audit."""
    # Authentication
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    
    # Rule Management
    RULE_CREATE = "RULE_CREATE"
    RULE_UPDATE = "RULE_UPDATE"
    RULE_DELETE = "RULE_DELETE"
    RULE_ENABLE = "RULE_ENABLE"
    RULE_DISABLE = "RULE_DISABLE"
    
    # Guardian Actions
    GUARDIAN_PAUSE_ATTEMPT = "GUARDIAN_PAUSE_ATTEMPT"
    GUARDIAN_PAUSE_SUCCESS = "GUARDIAN_PAUSE_SUCCESS"
    GUARDIAN_PAUSE_FAILED = "GUARDIAN_PAUSE_FAILED"
    GUARDIAN_PAUSE_OVERRIDE = "GUARDIAN_PAUSE_OVERRIDE"  # Manual override
    
    # Incident Management
    INCIDENT_RESOLVE = "INCIDENT_RESOLVE"
    INCIDENT_FALSE_POSITIVE = "INCIDENT_FALSE_POSITIVE"
    INCIDENT_ACKNOWLEDGE = "INCIDENT_ACKNOWLEDGE"
    
    # System Actions
    CHAIN_ADD = "CHAIN_ADD"
    CHAIN_REMOVE = "CHAIN_REMOVE"
    USER_CREATE = "USER_CREATE"
    USER_UPDATE = "USER_UPDATE"
    USER_DELETE = "USER_DELETE"


class AuditLogger:
    """
    Centralized audit logging.
    
    Logs all important actions for compliance and security.
    """
    
    @staticmethod
    def log(
        action_type: ActionType,
        actor_id: str,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None
    ):
        """
        Log an audit event.
        
        Args:
            action_type: Type of action
            actor_id: User ID or "system"
            resource_id: ID of affected resource (incident_id, rule_id, etc.)
            details: Additional context
            ip_address: IP address of actor
            old_value: Previous value (for updates)
            new_value: New value (for updates)
        """
        try:
            # Get database session - prioritize Cloud SQL Proxy Unix socket
            cloudsql_instance = os.getenv("CLOUDSQL_INSTANCE")
            database_url = os.getenv("DATABASE_URL")
            
            if cloudsql_instance:
                # Use Cloud SQL Proxy Unix socket
                socket_dir = f"/cloudsql/{cloudsql_instance}"
                db_user = os.getenv("POSTGRES_USER", "xdr")
                db_pass = os.getenv("POSTGRES_PASSWORD", "xdr_password")
                db_name = os.getenv("POSTGRES_DB", "web3_xdr")
                database_url = f"postgresql+psycopg2://{db_user}:{db_pass}@/{db_name}"
                engine = create_engine(
                    database_url,
                    connect_args={"host": socket_dir},
                    pool_pre_ping=True,
                    pool_size=2,
                    max_overflow=3
                )
            elif database_url:
                engine = create_engine(database_url, pool_pre_ping=True)
            else:
                database_url = f"postgresql://{os.getenv('POSTGRES_USER', 'xdr')}:{os.getenv('POSTGRES_PASSWORD', 'xdr_password')}@{os.getenv('POSTGRES_HOST', 'localhost')}:{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'web3_xdr')}"
                engine = create_engine(database_url, pool_pre_ping=True)
            
            SessionLocal = sessionmaker(bind=engine)
            session = SessionLocal()
            
            try:
                audit_log = AuditLogModel(
                    timestamp=datetime.now(timezone.utc),
                    action_type=action_type.value,
                    actor_id=actor_id,
                    resource_id=resource_id,
                    details=details or {},
                    ip_address=ip_address,
                    old_value=old_value,
                    new_value=new_value,
                    # Legacy fields for backward compatibility
                    action=action_type.value,
                    entity_type=details.get("entity_type", "unknown") if details else "unknown",
                    entity_id=resource_id,
                    user=actor_id
                )
                
                session.add(audit_log)
                session.commit()
                
                logger.info(
                    "audit_log_created",
                    action_type=action_type.value,
                    actor_id=actor_id,
                    resource_id=resource_id
                )
            finally:
                session.close()
        except Exception as e:
            # Fail-safe: Log to application logs if DB fails
            logger.error(
                "audit_log_failed",
                action_type=action_type.value,
                actor_id=actor_id,
                error=str(e)
            )
    
    @staticmethod
    def log_login(username: str, success: bool, ip_address: Optional[str] = None):
        """Log login attempt."""
        action = ActionType.LOGIN_SUCCESS if success else ActionType.LOGIN_FAILURE
        AuditLogger.log(
            action_type=action,
            actor_id=username,
            details={"username": username, "success": success},
            ip_address=ip_address
        )
    
    @staticmethod
    def log_guardian_pause(
        incident_id: str,
        protocol_id: str,
        contract_address: str,
        success: bool,
        actor_id: str = "system",
        tx_hash: Optional[str] = None,
        error: Optional[str] = None
    ):
        """Log guardian pause attempt."""
        action = ActionType.GUARDIAN_PAUSE_SUCCESS if success else ActionType.GUARDIAN_PAUSE_FAILED
        AuditLogger.log(
            action_type=action,
            actor_id=actor_id,
            resource_id=incident_id,
            details={
                "protocol_id": protocol_id,
                "contract_address": contract_address,
                "tx_hash": tx_hash,
                "error": error
            }
        )
    
    @staticmethod
    def log_rule_change(
        rule_id: str,
        action_type: ActionType,
        actor_id: str,
        old_value: Optional[Dict[str, Any]] = None,
        new_value: Optional[Dict[str, Any]] = None
    ):
        """Log rule creation/modification."""
        AuditLogger.log(
            action_type=action_type,
            actor_id=actor_id,
            resource_id=rule_id,
            old_value=old_value,
            new_value=new_value
        )
    
    @staticmethod
    def log_incident_status_change(
        incident_id: str,
        old_status: str,
        new_status: str,
        actor_id: str
    ):
        """Log incident status change."""
        AuditLogger.log(
            action_type=ActionType.INCIDENT_RESOLVE if new_status == "RESOLVED" else ActionType.INCIDENT_ACKNOWLEDGE,
            actor_id=actor_id,
            resource_id=incident_id,
            old_value={"status": old_status},
            new_value={"status": new_status}
        )

