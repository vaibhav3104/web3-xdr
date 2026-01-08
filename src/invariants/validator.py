"""
Rule Safety & Validation
========================

Phase 5: Validates rules before deployment and provides dry-run capability.
Prevents deploying noisy or incorrect rules.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import yaml
import structlog
from pydantic import BaseModel, ValidationError, Field

from ..database.models import EventModel
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os

logger = structlog.get_logger(__name__)


class RuleDetection(BaseModel):
    """Detection rule schema."""
    event_type: str = Field(..., description="Event type to detect")
    conditions: Dict[str, Any] = Field(..., description="Detection conditions")
    threshold: Optional[float] = Field(None, description="Threshold value")


class RuleThresholds(BaseModel):
    """Threshold configuration."""
    min_amount: Optional[float] = None
    max_amount: Optional[float] = None
    min_confidence: float = Field(0.5, ge=0.0, le=1.0)


class RuleSchema(BaseModel):
    """Complete rule schema validation."""
    rule_id: str = Field(..., min_length=1, max_length=128)
    name: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = None
    severity: str = Field(..., pattern="^(CRITICAL|HIGH|MEDIUM|LOW)$")
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    enabled: bool = True
    
    detection: RuleDetection
    thresholds: Optional[RuleThresholds] = None
    actions: Optional[List[Dict[str, Any]]] = None


class RuleValidator:
    """
    Validates rules before deployment.
    
    Features:
    - Schema validation (Pydantic)
    - Dry-run against historical events
    - Prevents noisy rules
    """
    
    def validate_schema(self, rule_yaml: str) -> tuple[bool, Optional[str], Optional[RuleSchema]]:
        """
        Validate rule schema.
        
        Args:
            rule_yaml: YAML string of rule definition
        
        Returns:
            (is_valid, error_message, parsed_rule)
        """
        try:
            # Parse YAML
            rule_dict = yaml.safe_load(rule_yaml)
            
            if not rule_dict:
                return False, "Empty rule definition", None
            
            # Validate with Pydantic
            rule = RuleSchema(**rule_dict)
            
            return True, None, rule
            
        except yaml.YAMLError as e:
            return False, f"Invalid YAML: {str(e)}", None
        except ValidationError as e:
            return False, f"Schema validation failed: {e.json()}", None
        except Exception as e:
            return False, f"Validation error: {str(e)}", None
    
    def dry_run(
        self,
        rule: RuleSchema,
        event_count: int = 10000,
        time_window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Dry-run rule against historical events.
        
        Args:
            rule: Validated rule schema
            event_count: Number of historical events to test
            time_window_hours: Time window for events
        
        Returns:
            Dictionary with hypothetical alert count and statistics
        """
        try:
            cutoff_time = datetime.now() - timedelta(hours=time_window_hours)
            
            # Get database session
            database_url = os.getenv("DATABASE_URL")
            if not database_url:
                database_url = f"postgresql://{os.getenv('POSTGRES_USER', 'xdr')}:{os.getenv('POSTGRES_PASSWORD', 'xdr_password')}@{os.getenv('POSTGRES_HOST', 'localhost')}:{os.getenv('POSTGRES_PORT', '5432')}/{os.getenv('POSTGRES_DB', 'web3_xdr')}"
            
            engine = create_engine(database_url)
            SessionLocal = sessionmaker(bind=engine)
            session = SessionLocal()
            
            try:
                # Get recent events
                events = session.query(EventModel).filter(
                    EventModel.block_timestamp >= cutoff_time
                ).limit(event_count).all()
                
                # Simulate rule evaluation
                alerts = []
                matched_events = []
                
                for event in events:
                    # Check if event matches rule
                    if self._event_matches_rule(event, rule):
                        matched_events.append(event)
                        
                        # Check thresholds
                        if self._check_thresholds(event, rule):
                            alerts.append({
                                "event_id": event.event_id,
                                "chain": event.chain_id,
                                "timestamp": event.block_timestamp.isoformat(),
                                "severity": rule.severity
                            })
                
                # Calculate statistics
                total_events = len(events)
                matched_count = len(matched_events)
                alert_count = len(alerts)
                
                # Calculate alert rate
                alert_rate = (alert_count / total_events * 100) if total_events > 0 else 0.0
                
                # Determine if rule is too noisy
                is_noisy = alert_rate > 10.0  # More than 10% alert rate
                
                return {
                    "rule_id": rule.rule_id,
                    "rule_name": rule.name,
                    "total_events_tested": total_events,
                    "matched_events": matched_count,
                    "hypothetical_alerts": alert_count,
                    "alert_rate_percent": round(alert_rate, 2),
                    "is_noisy": is_noisy,
                    "time_window_hours": time_window_hours,
                    "sample_alerts": alerts[:10],  # First 10 alerts as sample
                    "recommendation": self._generate_recommendation(alert_rate, matched_count)
                }
            finally:
                session.close()
                
        except Exception as e:
            logger.error("dry_run_failed", rule_id=rule.rule_id, error=str(e))
            return {
                "rule_id": rule.rule_id,
                "error": str(e),
                "hypothetical_alerts": 0
            }
    
    def _event_matches_rule(self, event: EventModel, rule: RuleSchema) -> bool:
        """Check if event matches rule detection criteria."""
        detection = rule.detection
        
        # Check event type
        if detection.event_type and event.event_type != detection.event_type:
            return False
        
        # Check conditions
        conditions = detection.conditions
        
        # Check severity
        if "severity" in conditions:
            if event.severity != conditions["severity"]:
                return False
        
        # Check chain
        if "chain_id" in conditions:
            if event.chain_id not in conditions["chain_id"]:
                return False
        
        # Check contract address
        if "contract_address" in conditions:
            if event.contract_address.lower() != conditions["contract_address"].lower():
                return False
        
        # Check amount range
        if "amount_min" in conditions and event.amount:
            if event.amount < conditions["amount_min"]:
                return False
        
        if "amount_max" in conditions and event.amount:
            if event.amount > conditions["amount_max"]:
                return False
        
        return True
    
    def _check_thresholds(self, event: EventModel, rule: RuleSchema) -> bool:
        """Check if event passes threshold checks."""
        if not rule.thresholds:
            return True
        
        thresholds = rule.thresholds
        
        # Check min amount
        if thresholds.min_amount and event.amount:
            if event.amount < thresholds.min_amount:
                return False
        
        # Check max amount
        if thresholds.max_amount and event.amount:
            if event.amount > thresholds.max_amount:
                return False
        
        # Check confidence (would need to be calculated, for now assume pass)
        # In real implementation, calculate confidence from event data
        
        return True
    
    def _generate_recommendation(self, alert_rate: float, matched_count: int) -> str:
        """Generate recommendation based on dry-run results."""
        if alert_rate > 50.0:
            return "⚠️  CRITICAL: Rule is extremely noisy (>50% alert rate). Consider tightening conditions or disabling."
        elif alert_rate > 10.0:
            return "⚠️  WARNING: Rule may be too noisy (>10% alert rate). Consider refining conditions."
        elif alert_rate > 1.0:
            return "ℹ️  INFO: Rule has moderate alert rate. Monitor after deployment."
        elif matched_count == 0:
            return "ℹ️  INFO: Rule matched no events in test window. May be too restrictive or no matching events exist."
        else:
            return "✅ Rule looks good. Alert rate is acceptable."

