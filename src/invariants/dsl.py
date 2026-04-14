"""YAML-based Domain Specific Language for custom invariants."""
import yaml
import operator
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from decimal import Decimal
from pathlib import Path

import structlog

from src.invariants.base import Invariant, InvariantContext
from src.models.invariants import InvariantResult, InvariantType
from src.models.events import SecurityEvent, Severity

logger = structlog.get_logger()

# Operator mapping for conditions
OPERATORS: Dict[str, Callable] = {
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "eq": operator.eq,
    "ne": operator.ne,
    ">": operator.gt,
    ">=": operator.ge,
    "<": operator.lt,
    "<=": operator.le,
    "==": operator.eq,
    "!=": operator.ne,
}


@dataclass
class DSLCondition:
    """A single condition in a DSL invariant."""
    field: str  # e.g., "event.amount_usd", "state.total_minted", "context.tvl_change_pct"
    operator: str  # gt, gte, lt, lte, eq, ne
    value: Any  # threshold value (can reference other fields with $)

    def evaluate(self, event: SecurityEvent, context: InvariantContext, state: Dict) -> bool:
        """Evaluate this condition against an event."""
        actual = self._resolve_field(self.field, event, context, state)
        expected = self._resolve_value(self.value, event, context, state)

        if actual is None or expected is None:
            return False

        op_func = OPERATORS.get(self.operator)
        if not op_func:
            return False

        try:
            return op_func(float(actual), float(expected))
        except (ValueError, TypeError):
            return False

    def _resolve_field(
        self,
        field_path: str,
        event: SecurityEvent,
        context: InvariantContext,
        state: Dict,
    ) -> Any:
        """Resolve a dotted field path to a value."""
        parts = field_path.split(".", 1)
        scope = parts[0]
        attr = parts[1] if len(parts) > 1 else ""

        if scope == "event":
            return getattr(event, attr, None)
        elif scope == "state":
            return state.get(attr)
        elif scope == "context":
            bridge_id = getattr(event, "bridge_id", None) or ""
            bridge_state = context.get_bridge_state(bridge_id)

            if attr == "tvl_change_pct":
                # Use imbalance as a proxy for TVL change
                minted = bridge_state.get("minted", Decimal("0"))
                locked = bridge_state.get("locked", Decimal("0"))
                if locked > 0:
                    return float((minted - locked) / locked * 100)
                return 0.0
            elif attr == "total_locked":
                return float(bridge_state.get("locked", Decimal("0")))
            elif attr == "total_minted":
                return float(bridge_state.get("minted", Decimal("0")))
            elif attr == "event_count_last_hour":
                events = context.get_recent_events(minutes=60)
                return len(events)

            return state.get(attr)
        return None

    def _resolve_value(
        self,
        value: Any,
        event: SecurityEvent,
        context: InvariantContext,
        state: Dict,
    ) -> Any:
        """Resolve a value, which may be a field reference ($field.path) or literal."""
        if isinstance(value, str) and value.startswith("$"):
            return self._resolve_field(value[1:], event, context, state)
        return value


@dataclass
class DSLInvariantDef:
    """Parsed definition of a YAML-defined invariant."""
    name: str
    description: str
    invariant_type: str  # economic, temporal, governance, velocity, threshold
    severity: str  # low, medium, high, critical
    enabled: bool = True
    chains: List[str] = field(default_factory=list)  # empty = all chains
    event_types: List[str] = field(default_factory=list)  # filter events
    conditions: List[DSLCondition] = field(default_factory=list)
    match_mode: str = "all"  # "all" (AND) or "any" (OR)
    cooldown_seconds: int = 60
    confidence: float = 0.8
    metadata: Dict[str, Any] = field(default_factory=dict)


class DSLInvariant(Invariant):
    """An invariant created from YAML DSL definition."""

    def __init__(self, definition: DSLInvariantDef):
        self.definition = definition
        self.name = definition.name
        self.description = definition.description
        self.invariant_type = self._map_type(definition.invariant_type)
        self.severity = self._map_severity(definition.severity)
        self.enabled = definition.enabled
        self.cooldown_seconds = definition.cooldown_seconds
        self._last_triggered: Dict[str, datetime] = {}  # per-chain cooldown
        self._state: Dict[str, Any] = {}
        # Call parent init for _last_violation tracking
        super().__init__()

    def _map_type(self, type_str: str) -> InvariantType:
        mapping = {
            "economic": InvariantType.ECONOMIC,
            "temporal": InvariantType.TEMPORAL,
            "governance": InvariantType.GOVERNANCE,
            "velocity": InvariantType.VELOCITY,
            "threshold": InvariantType.THRESHOLD,
        }
        return mapping.get(type_str.lower(), InvariantType.THRESHOLD)

    def _map_severity(self, sev_str: str) -> Severity:
        mapping = {
            "info": Severity.INFO,
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }
        return mapping.get(sev_str.lower(), Severity.MEDIUM)

    async def evaluate(self, context: InvariantContext) -> InvariantResult:
        """
        Evaluate this DSL invariant against the most recent events in context.

        The base Invariant ABC expects (context) only.  We pull the latest
        events from the context and check each one against the DSL conditions.
        """
        # Get recent events to evaluate against
        recent_events = context.get_recent_events(minutes=5)

        # Filter by event type if specified
        if self.definition.event_types:
            upper_types = [et.upper() for et in self.definition.event_types]
            recent_events = [
                e for e in recent_events
                if (e.event_type.value if hasattr(e.event_type, "value") else str(e.event_type)).upper() in upper_types
            ]

        for event in recent_events:
            result = self._evaluate_event(event, context)
            if result and result.violated:
                self.record_violation()
                return result

        return InvariantResult(
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            violated=False,
            severity=Severity.INFO,
            description=self.definition.description,
        )

    def _evaluate_event(
        self, event: SecurityEvent, context: InvariantContext
    ) -> Optional[InvariantResult]:
        """Evaluate a single event against DSL conditions."""
        # Chain filter
        if self.definition.chains and event.chain_id not in self.definition.chains:
            return None

        # Cooldown check
        cooldown_key = f"{event.chain_id}:{self.name}"
        last = self._last_triggered.get(cooldown_key)
        if last and (datetime.now(timezone.utc) - last).total_seconds() < self.definition.cooldown_seconds:
            return None

        # Evaluate conditions
        results = [
            cond.evaluate(event, context, self._state)
            for cond in self.definition.conditions
        ]

        if self.definition.match_mode == "all":
            violated = all(results) if results else False
        else:
            violated = any(results) if results else False

        if not violated:
            return None

        self._last_triggered[cooldown_key] = datetime.now(timezone.utc)

        return InvariantResult(
            invariant_name=self.name,
            invariant_type=self.invariant_type,
            violated=True,
            severity=self._map_severity(self.definition.severity),
            confidence=self.definition.confidence,
            chain_id=event.chain_id,
            bridge_id=getattr(event, "bridge_id", None),
            description=self.definition.description,
            related_event_ids=[event.event_id],
            evidence={
                "dsl_invariant": self.name,
                "conditions_evaluated": len(self.definition.conditions),
                "match_mode": self.definition.match_mode,
                "event_type": str(event.event_type),
                "tx_hash": event.tx_hash,
            },
        )


class DSLLoader:
    """Loads invariant definitions from YAML files."""

    @staticmethod
    def load_file(path: str) -> List[DSLInvariantDef]:
        """Load invariant definitions from a YAML file."""
        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not data:
            return []

        invariants_data = data if isinstance(data, list) else data.get("invariants", [data])
        return [DSLLoader._parse_definition(inv) for inv in invariants_data]

    @staticmethod
    def load_directory(directory: str) -> List[DSLInvariantDef]:
        """Load all YAML invariant definitions from a directory."""
        defs: List[DSLInvariantDef] = []
        path = Path(directory)
        if not path.exists():
            return defs

        for f in sorted(path.glob("*.yaml")):
            try:
                defs.extend(DSLLoader.load_file(str(f)))
            except Exception as e:
                logger.warning("dsl_load_error", file=str(f), error=str(e))
                continue
        for f in sorted(path.glob("*.yml")):
            try:
                defs.extend(DSLLoader.load_file(str(f)))
            except Exception as e:
                logger.warning("dsl_load_error", file=str(f), error=str(e))
                continue
        return defs

    @staticmethod
    def load_string(yaml_str: str) -> List[DSLInvariantDef]:
        """Load invariant definitions from a YAML string."""
        data = yaml.safe_load(yaml_str)
        if not data:
            return []
        invariants_data = data if isinstance(data, list) else data.get("invariants", [data])
        return [DSLLoader._parse_definition(inv) for inv in invariants_data]

    @staticmethod
    def _parse_definition(data: Dict) -> DSLInvariantDef:
        """Parse a single invariant definition from dict."""
        conditions = []
        for cond_data in data.get("conditions", []):
            conditions.append(DSLCondition(
                field=cond_data["field"],
                operator=cond_data["operator"],
                value=cond_data["value"],
            ))

        return DSLInvariantDef(
            name=data["name"],
            description=data.get("description", ""),
            invariant_type=data.get("type", "threshold"),
            severity=data.get("severity", "medium"),
            enabled=data.get("enabled", True),
            chains=data.get("chains", []),
            event_types=data.get("event_types", []),
            conditions=conditions,
            match_mode=data.get("match_mode", "all"),
            cooldown_seconds=data.get("cooldown_seconds", 60),
            confidence=data.get("confidence", 0.8),
            metadata=data.get("metadata", {}),
        )

    @staticmethod
    def create_invariants(definitions: List[DSLInvariantDef]) -> List[DSLInvariant]:
        """Create Invariant instances from definitions."""
        return [DSLInvariant(d) for d in definitions if d.enabled]
