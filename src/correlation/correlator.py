"""
XDR Correlator - Main correlation engine.
"""

from datetime import datetime, timedelta, timezone
from typing import Awaitable, Any, Callable, Dict, List, Optional, Set
import asyncio
import structlog

from ..models.events import SecurityEvent
from ..models.invariants import InvariantResult
from .entity_graph import EntityGraph, EntityGraphBuilder
from .pattern_matcher import AttackPatternMatcher, PatternMatch
from .incident_builder import IncidentBuilder, Incident, IncidentStatus

logger = structlog.get_logger()


class XDRCorrelator:
    """
    Extended Detection and Response Correlator.
    
    Core responsibilities:
    - Aggregate related violations into incidents
    - Match attack patterns
    - Track entity relationships
    - Merge overlapping incidents
    - Route incidents to handlers
    """
    
    def __init__(self):
        # Components
        self.entity_graph_builder = EntityGraphBuilder()
        self.pattern_matcher = AttackPatternMatcher()
        self.incident_builder = IncidentBuilder()
        
        # Incident management
        self.active_incidents: Dict[str, Incident] = {}
        self.incident_handlers: List[Callable[[Incident], Awaitable[Any]]] = []
        
        # Pending violations for aggregation
        self._pending_violations: List[InvariantResult] = []
        self._pending_events: List[SecurityEvent] = []
        self._last_aggregation: datetime = datetime.now(timezone.utc)
        
        # Configuration
        self.aggregation_window = timedelta(minutes=5)
        self.incident_merge_window = timedelta(hours=1)
        
        # Statistics
        self._stats = {
            "events_processed": 0,
            "violations_received": 0,
            "incidents_created": 0,
            "patterns_matched": 0,
        }
    
    def add_incident_handler(
        self,
        handler: Callable[[Incident], Awaitable[Any]]
    ):
        """Add a handler for new incidents."""
        self.incident_handlers.append(handler)
    
    async def process_event(self, event: SecurityEvent):
        """
        Process a security event.
        
        Updates entity graph and buffers for correlation.
        """
        # Update entity graph
        await self.entity_graph_builder.process_event(event)
        
        # Buffer for pattern matching
        self._pending_events.append(event)
        
        # Prune old events
        cutoff = datetime.now(timezone.utc) - timedelta(hours=2)
        self._pending_events = [
            e for e in self._pending_events
            if e.block_timestamp > cutoff
        ]
        
        self._stats["events_processed"] += 1
    
    async def process_violation(self, violation: InvariantResult):
        """
        Process an invariant violation.
        
        Buffers violations for aggregation into incidents.
        """
        self._pending_violations.append(violation)
        self._stats["violations_received"] += 1
        
        logger.info(
            "violation_received",
            invariant=violation.invariant_name,
            severity=violation.severity.name
        )
        
        # Check if we should aggregate now
        if self._should_aggregate():
            await self._aggregate_violations()
    
    def _should_aggregate(self) -> bool:
        """Check if we should run aggregation."""
        # Aggregate if we have critical violations
        if any(v.severity.name == "CRITICAL" for v in self._pending_violations):
            return True
        
        # Aggregate if we have multiple violations
        if len(self._pending_violations) >= 3:
            return True
        
        # Aggregate on time window
        elapsed = datetime.now(timezone.utc) - self._last_aggregation
        if elapsed > self.aggregation_window and self._pending_violations:
            return True
        
        return False
    
    async def _aggregate_violations(self):
        """
        Aggregate pending violations into incidents.
        """
        if not self._pending_violations:
            return
        
        logger.debug(
            "aggregating_violations",
            count=len(self._pending_violations)
        )
        
        # Group violations by bridge/chain
        groups = self._group_violations(self._pending_violations)
        
        for group in groups:
            # Find related events
            related_events = self._find_related_events(group)
            
            # Match patterns
            pattern_matches = await self.pattern_matcher.match_events(
                related_events
            )
            self._stats["patterns_matched"] += len(pattern_matches)
            
            # Check if matches existing incident
            existing = self._find_matching_incident(group)
            
            if existing:
                # Update existing incident
                await self._update_incident(existing, group, pattern_matches, related_events)
            else:
                # Create new incident
                await self._create_incident(group, pattern_matches, related_events)
        
        # Clear processed violations
        self._pending_violations.clear()
        self._last_aggregation = datetime.now(timezone.utc)
    
    def _group_violations(
        self,
        violations: List[InvariantResult]
    ) -> List[List[InvariantResult]]:
        """
        Group related violations together.
        """
        # Group by bridge_id and chain
        groups: Dict[str, List[InvariantResult]] = {}
        
        for violation in violations:
            key = f"{violation.bridge_id or 'unknown'}:{violation.chain_id or 'unknown'}"
            if key not in groups:
                groups[key] = []
            groups[key].append(violation)
        
        return list(groups.values())
    
    def _find_related_events(
        self,
        violations: List[InvariantResult]
    ) -> List[SecurityEvent]:
        """
        Find events related to the violations.
        """
        related_event_ids: Set[str] = set()
        
        for violation in violations:
            related_event_ids.update(violation.related_event_ids)
        
        # Get events from buffer
        related = [
            e for e in self._pending_events
            if e.event_id in related_event_ids
        ]
        
        # Also get events from same bridge/time window
        bridge_ids = {v.bridge_id for v in violations if v.bridge_id}
        earliest = min(v.timestamp for v in violations)
        window_start = earliest - timedelta(minutes=30)
        
        for event in self._pending_events:
            if event.event_id in related_event_ids:
                continue
            if event.bridge_id in bridge_ids and event.block_timestamp > window_start:
                related.append(event)
        
        return related
    
    def _find_matching_incident(
        self,
        violations: List[InvariantResult]
    ) -> Optional[Incident]:
        """
        Find an existing incident that matches these violations.
        """
        cutoff = datetime.now(timezone.utc) - self.incident_merge_window

        # Get bridges from violations
        bridge_ids = {v.bridge_id for v in violations if v.bridge_id}

        for incident in self.active_incidents.values():
            # Skip closed incidents
            if incident.status in (IncidentStatus.RESOLVED, IncidentStatus.FALSE_POSITIVE):
                continue

            # Check if same protocol
            if incident.protocol_id not in bridge_ids:
                continue

            # Check time window
            if incident.created_at < cutoff:
                continue

            return incident

        return None
    
    async def _create_incident(
        self,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch],
        events: List[SecurityEvent]
    ):
        """
        Create a new incident via IncidentBuilder.upsert_incident().
        """
        incident = None
        for violation in violations:
            # Find the most relevant event for this violation
            event = self._find_event_for_violation(violation, events)
            if event:
                incident = self.incident_builder.upsert_incident(violation, event)

        if not incident:
            return

        # Store incident
        self.active_incidents[incident.incident_id] = incident
        self._stats["incidents_created"] += 1

        # Notify handlers
        await self._notify_handlers(incident)

        logger.warning(
            "incident_created",
            incident_id=incident.incident_id,
            attack_type=incident.attack_type,
            severity=incident.severity.name,
            total_loss=str(incident.total_value_at_risk_usd)
        )

    def _find_event_for_violation(
        self,
        violation: InvariantResult,
        events: List[SecurityEvent]
    ) -> Optional[SecurityEvent]:
        """Find the most relevant event for a violation."""
        # Try matching by event IDs in the violation
        for event in events:
            if event.event_id in violation.related_event_ids:
                return event
        # Fall back to first event
        return events[0] if events else None
    
    async def _update_incident(
        self,
        incident: Incident,
        violations: List[InvariantResult],
        pattern_matches: List[PatternMatch],
        events: List[SecurityEvent]
    ):
        """
        Update an existing incident with new information.
        """
        for violation in violations:
            event = self._find_event_for_violation(violation, events)
            if event:
                incident.add_violation(violation, event)

        incident.updated_at = datetime.now(timezone.utc)

        logger.info(
            "incident_updated",
            incident_id=incident.incident_id,
            new_violations=len(violations)
        )

        # Notify handlers of update
        await self._notify_handlers(incident)
    
    async def _notify_handlers(self, incident: Incident):
        """Notify all handlers of an incident."""
        await asyncio.gather(
            *[handler(incident) for handler in self.incident_handlers],
            return_exceptions=True
        )
    
    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get an incident by ID."""
        return self.active_incidents.get(incident_id)
    
    def get_active_incidents(self) -> List[Incident]:
        """Get all active incidents."""
        return [
            i for i in self.active_incidents.values()
            if i.status in (IncidentStatus.OPEN_PENDING, IncidentStatus.OPEN_CONFIRMED)
        ]

    def acknowledge_incident(self, incident_id: str, user: str) -> bool:
        """Acknowledge an incident."""
        incident = self.active_incidents.get(incident_id)
        if incident:
            incident.status = IncidentStatus.OPEN_CONFIRMED
            incident.updated_at = datetime.now(timezone.utc)
            return True
        return False

    def resolve_incident(
        self,
        incident_id: str,
        resolution: str = "resolved"
    ) -> bool:
        """Resolve an incident."""
        incident = self.active_incidents.get(incident_id)
        if incident:
            if resolution == "false_positive":
                incident.status = IncidentStatus.FALSE_POSITIVE
            else:
                incident.status = IncidentStatus.RESOLVED
            incident.updated_at = datetime.now(timezone.utc)
            return True
        return False
    
    def get_stats(self) -> dict:
        """Get correlator statistics."""
        return {
            **self._stats,
            "active_incidents": len(self.get_active_incidents()),
            "total_incidents": len(self.active_incidents),
            "entity_graph": self.entity_graph_builder.get_stats(),
        }
    
    async def force_aggregation(self):
        """Force immediate aggregation (for testing/manual trigger)."""
        await self._aggregate_violations()

