"""
Forensics Engine for Sentinel3 XDR.
Provides historical investigation, incident replay, and fund-flow tracing.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
from enum import Enum


class ForensicQueryType(Enum):
    ADDRESS_HISTORY = "address_history"
    INCIDENT_REPLAY = "incident_replay"
    BLOCK_RANGE_SCAN = "block_range_scan"
    FUND_FLOW_TRACE = "fund_flow_trace"
    PATTERN_SEARCH = "pattern_search"


@dataclass
class ForensicQuery:
    query_type: ForensicQueryType
    chain_ids: List[str] = field(default_factory=list)
    addresses: List[str] = field(default_factory=list)
    start_block: Optional[int] = None
    end_block: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    incident_id: Optional[str] = None
    max_depth: int = 5  # For fund flow tracing
    include_related: bool = True


@dataclass
class TimelineEntry:
    timestamp: datetime
    chain_id: str
    event_type: str
    tx_hash: str
    block_number: int
    description: str
    amount_usd: Optional[float] = None
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    severity: str = "info"
    is_violation: bool = False


@dataclass
class ForensicReport:
    query: ForensicQuery
    created_at: datetime = field(default_factory=datetime.utcnow)
    timeline: List[TimelineEntry] = field(default_factory=list)
    fund_flows: List[Dict[str, Any]] = field(default_factory=list)
    violations_found: List[Dict[str, Any]] = field(default_factory=list)
    affected_addresses: List[str] = field(default_factory=list)
    affected_chains: List[str] = field(default_factory=list)
    total_loss_usd: float = 0.0
    summary: str = ""
    attack_pattern: Optional[str] = None


class ForensicsEngine:
    """Historical investigation and incident replay engine."""

    def __init__(self, db_service=None, invariant_engine=None, entity_graph=None):
        self.db_service = db_service
        self.invariant_engine = invariant_engine
        self.entity_graph = entity_graph
        self._running_queries: Dict[str, ForensicQuery] = {}

    async def investigate(self, query: ForensicQuery) -> ForensicReport:
        """Run a forensic investigation based on query type."""
        report = ForensicReport(query=query)

        if query.query_type == ForensicQueryType.ADDRESS_HISTORY:
            await self._investigate_address(query, report)
        elif query.query_type == ForensicQueryType.INCIDENT_REPLAY:
            await self._replay_incident(query, report)
        elif query.query_type == ForensicQueryType.BLOCK_RANGE_SCAN:
            await self._scan_block_range(query, report)
        elif query.query_type == ForensicQueryType.FUND_FLOW_TRACE:
            await self._trace_fund_flows(query, report)
        elif query.query_type == ForensicQueryType.PATTERN_SEARCH:
            await self._search_patterns(query, report)

        report.summary = self._generate_summary(report)
        return report

    async def _investigate_address(self, query: ForensicQuery, report: ForensicReport):
        """Get full history of an address across all chains."""
        from src.database.service import DatabaseService

        for address in query.addresses:
            events = await DatabaseService.query_events_by_address(
                address=address,
                chain_ids=query.chain_ids or None,
                start_time=query.start_time,
                end_time=query.end_time,
                limit=1000,
            )
            for event in events:
                entry = TimelineEntry(
                    timestamp=event.get("block_timestamp", datetime.utcnow()),
                    chain_id=event.get("chain_id", "unknown"),
                    event_type=event.get("event_type", "unknown"),
                    tx_hash=event.get("tx_hash", ""),
                    block_number=event.get("block_number", 0),
                    description=f"{event.get('event_type', 'Event')} on {event.get('chain_id', 'unknown')}",
                    amount_usd=float(event.get("amount_usd", 0) or 0),
                    from_address=event.get("from_address"),
                    to_address=event.get("to_address"),
                    severity=event.get("severity", "info"),
                )
                report.timeline.append(entry)

        report.timeline.sort(key=lambda e: e.timestamp)
        report.affected_addresses = list(query.addresses)
        report.affected_chains = list(set(e.chain_id for e in report.timeline))

    async def _replay_incident(self, query: ForensicQuery, report: ForensicReport):
        """Replay an incident by re-running invariants against stored events."""
        from src.database.service import DatabaseService

        if not query.incident_id:
            return

        # Get the incident and its events
        incident = await DatabaseService.get_incident_by_id(query.incident_id)
        if not incident:
            report.summary = f"Incident {query.incident_id} not found"
            return

        event_ids = incident.get("event_ids", []) or []
        events = []
        for eid in event_ids:
            event = await DatabaseService.get_event_by_id(eid)
            if event:
                events.append(event)

        events.sort(key=lambda e: e.get("block_timestamp", datetime.min))

        # Build timeline from events
        for event in events:
            entry = TimelineEntry(
                timestamp=event.get("block_timestamp", datetime.utcnow()),
                chain_id=event.get("chain_id", "unknown"),
                event_type=event.get("event_type", "unknown"),
                tx_hash=event.get("tx_hash", ""),
                block_number=event.get("block_number", 0),
                description=(
                    f"{event.get('event_type', 'Event')}: "
                    f"{event.get('amount_usd', 0)} USD on {event.get('chain_id')}"
                ),
                amount_usd=float(event.get("amount_usd", 0) or 0),
                from_address=event.get("from_address"),
                to_address=event.get("to_address"),
                severity=event.get("severity", "info"),
            )
            report.timeline.append(entry)

        # Re-run invariant checks on events to find violations
        if self.invariant_engine:
            for event_data in events:
                try:
                    from src.models.events import SecurityEvent

                    se = SecurityEvent(
                        **{
                            k: v
                            for k, v in event_data.items()
                            if k in SecurityEvent.__dataclass_fields__
                        }
                    )
                    results = await self.invariant_engine.process_event(se)
                    for r in results or []:
                        if r.violated:
                            report.violations_found.append(
                                {
                                    "invariant": r.invariant_name,
                                    "type": (
                                        r.invariant_type.value
                                        if hasattr(r.invariant_type, "value")
                                        else str(r.invariant_type)
                                    ),
                                    "severity": (
                                        r.severity.value
                                        if hasattr(r.severity, "value")
                                        else str(r.severity)
                                    ),
                                    "description": r.description,
                                    "amount_usd": float(r.violation_amount_usd or 0),
                                    "event_id": event_data.get("event_id"),
                                }
                            )
                except Exception:
                    pass

        report.total_loss_usd = float(incident.get("total_loss_usd", 0) or 0)
        report.attack_pattern = incident.get("attack_type")
        report.affected_chains = incident.get("affected_chains", []) or []

    async def _scan_block_range(self, query: ForensicQuery, report: ForensicReport):
        """Scan a specific block range for suspicious activity."""
        from src.database.service import DatabaseService

        for chain_id in query.chain_ids or ["ethereum"]:
            events = await DatabaseService.query_events_by_block_range(
                chain_id=chain_id,
                start_block=query.start_block or 0,
                end_block=query.end_block or 99999999,
                limit=2000,
            )
            for event in events:
                entry = TimelineEntry(
                    timestamp=event.get("block_timestamp", datetime.utcnow()),
                    chain_id=chain_id,
                    event_type=event.get("event_type", "unknown"),
                    tx_hash=event.get("tx_hash", ""),
                    block_number=event.get("block_number", 0),
                    description=f"Block {event.get('block_number')}: {event.get('event_type')}",
                    amount_usd=float(event.get("amount_usd", 0) or 0),
                    from_address=event.get("from_address"),
                    to_address=event.get("to_address"),
                    severity=event.get("severity", "info"),
                )
                report.timeline.append(entry)

        report.timeline.sort(key=lambda e: e.timestamp)
        report.affected_chains = list(query.chain_ids or [])

    async def _trace_fund_flows(self, query: ForensicQuery, report: ForensicReport):
        """Trace fund movements from a set of addresses."""
        if not query.addresses:
            return

        visited: set = set()
        queue = [(addr, 0) for addr in query.addresses]

        from src.database.service import DatabaseService

        while queue:
            address, depth = queue.pop(0)
            if depth > query.max_depth or address in visited:
                continue
            visited.add(address)

            events = await DatabaseService.query_events_by_address(
                address=address,
                start_time=query.start_time,
                end_time=query.end_time,
                limit=500,
            )

            for event in events:
                flow = {
                    "from": event.get("from_address", address),
                    "to": event.get("to_address", ""),
                    "amount_usd": float(event.get("amount_usd", 0) or 0),
                    "chain_id": event.get("chain_id", "unknown"),
                    "tx_hash": event.get("tx_hash", ""),
                    "timestamp": str(event.get("block_timestamp", "")),
                    "event_type": event.get("event_type", ""),
                    "depth": depth,
                }
                report.fund_flows.append(flow)

                # Add destination to queue for further tracing
                dest = event.get("to_address")
                if dest and dest not in visited:
                    queue.append((dest, depth + 1))

        report.affected_addresses = list(visited)
        report.total_loss_usd = sum(f.get("amount_usd", 0) for f in report.fund_flows)

    async def _search_patterns(self, query: ForensicQuery, report: ForensicReport):
        """Search for known attack patterns in historical data."""
        from src.database.service import DatabaseService

        events = await DatabaseService.query_events_by_block_range(
            chain_id=query.chain_ids[0] if query.chain_ids else "ethereum",
            start_block=query.start_block or 0,
            end_block=query.end_block or 99999999,
            limit=5000,
        )

        # Group events by block to find single-block patterns (flash loans)
        blocks: Dict[int, list] = {}
        for event in events:
            bn = event.get("block_number", 0)
            blocks.setdefault(bn, []).append(event)

        for block_num, block_events in blocks.items():
            if len(block_events) >= 3:
                types = [e.get("event_type", "") for e in block_events]
                # Flash loan pattern: borrow + action + repay in same block
                if any("BORROW" in t.upper() or "FLASH" in t.upper() for t in types):
                    report.violations_found.append(
                        {
                            "pattern": "flash_loan_single_block",
                            "block": block_num,
                            "chain": query.chain_ids[0] if query.chain_ids else "ethereum",
                            "event_count": len(block_events),
                            "description": (
                                f"Potential flash loan pattern in block {block_num}: "
                                f"{len(block_events)} events"
                            ),
                        }
                    )

        for event in events:
            entry = TimelineEntry(
                timestamp=event.get("block_timestamp", datetime.utcnow()),
                chain_id=event.get("chain_id", "unknown"),
                event_type=event.get("event_type", "unknown"),
                tx_hash=event.get("tx_hash", ""),
                block_number=event.get("block_number", 0),
                description=f"{event.get('event_type')} at block {event.get('block_number')}",
                amount_usd=float(event.get("amount_usd", 0) or 0),
                from_address=event.get("from_address"),
                to_address=event.get("to_address"),
            )
            report.timeline.append(entry)

    def _generate_summary(self, report: ForensicReport) -> str:
        """Generate a human-readable summary of findings."""
        parts = []
        parts.append(f"Investigation type: {report.query.query_type.value}")
        parts.append(f"Timeline events: {len(report.timeline)}")

        if report.violations_found:
            parts.append(f"Violations found: {len(report.violations_found)}")
        if report.fund_flows:
            parts.append(f"Fund flows traced: {len(report.fund_flows)}")
        if report.total_loss_usd > 0:
            parts.append(f"Total loss: ${report.total_loss_usd:,.2f}")
        if report.affected_chains:
            parts.append(f"Chains affected: {', '.join(report.affected_chains)}")
        if report.affected_addresses:
            parts.append(f"Addresses involved: {len(report.affected_addresses)}")
        if report.attack_pattern:
            parts.append(f"Attack pattern: {report.attack_pattern}")

        return " | ".join(parts)
