"""
TP/FP Feedback Loop with Auto-Suppression

Tracks per-rule TP/FP ratios over rolling windows and automatically
suppresses rules that exceed configurable FP thresholds. Exposes
Prometheus metrics for drift detection.

Integration:
    from src.rules.feedback_loop import get_feedback_loop

    loop = get_feedback_loop()

    # After analyst marks incident:
    loop.record_feedback(rule_id="whale-transfer-ft001", is_tp=True)
    loop.record_feedback(rule_id="velocity-spike-201", is_tp=False)

    # During rule evaluation (in engine.evaluate):
    if loop.is_suppressed("some-rule-id"):
        continue  # skip this rule

    # Periodic check (e.g., every 5 min via scheduler):
    actions = loop.evaluate_rules()
    # actions = [("velocity-spike-201", "auto_disabled", 0.95), ...]
"""

import os
from datetime import datetime, timedelta, timezone
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional
import structlog

logger = structlog.get_logger("feedback_loop")

# Try importing Prometheus metrics
try:
    from prometheus_client import Counter, Gauge
    PROM_AVAILABLE = True
except ImportError:
    PROM_AVAILABLE = False


@dataclass
class RuleStats:
    """Rolling TP/FP statistics for a single rule."""
    rule_id: str
    tp_timestamps: List[datetime] = field(default_factory=list)
    fp_timestamps: List[datetime] = field(default_factory=list)
    suppressed: bool = False
    suppressed_at: Optional[datetime] = None
    auto_disabled: bool = False
    auto_disabled_at: Optional[datetime] = None

    @property
    def total(self) -> int:
        return len(self.tp_timestamps) + len(self.fp_timestamps)

    @property
    def fp_count(self) -> int:
        return len(self.fp_timestamps)

    @property
    def tp_count(self) -> int:
        return len(self.tp_timestamps)

    @property
    def fp_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return self.fp_count / self.total

    def prune(self, window: timedelta):
        """Remove entries older than the rolling window."""
        cutoff = datetime.now(timezone.utc) - window
        self.tp_timestamps = [t for t in self.tp_timestamps if t > cutoff]
        self.fp_timestamps = [t for t in self.fp_timestamps if t > cutoff]


class FeedbackLoop:
    """
    Tracks per-rule TP/FP ratios and auto-suppresses noisy rules.

    Config (env vars):
        FEEDBACK_WINDOW_HOURS    — rolling window for ratio calc (default 168 = 7 days)
        FEEDBACK_FP_THRESHOLD    — FP rate to trigger suppression (default 0.80 = 80%)
        FEEDBACK_MIN_SAMPLES     — minimum incidents before evaluating (default 5)
        FEEDBACK_AUTO_DISABLE_FP — FP rate to auto-disable rule entirely (default 0.95)
        FEEDBACK_COOLDOWN_HOURS  — hours before re-evaluating a suppressed rule (default 24)
    """

    def __init__(self):
        self._window_hours = int(os.getenv("FEEDBACK_WINDOW_HOURS", "168"))
        self._fp_threshold = float(os.getenv("FEEDBACK_FP_THRESHOLD", "0.80"))
        self._min_samples = int(os.getenv("FEEDBACK_MIN_SAMPLES", "5"))
        self._auto_disable_fp = float(os.getenv("FEEDBACK_AUTO_DISABLE_FP", "0.95"))
        self._cooldown_hours = int(os.getenv("FEEDBACK_COOLDOWN_HOURS", "24"))

        self._window = timedelta(hours=self._window_hours)
        self._cooldown = timedelta(hours=self._cooldown_hours)

        self._stats: Dict[str, RuleStats] = defaultdict(lambda: RuleStats(rule_id=""))
        self._suppressed_rules: Dict[str, datetime] = {}  # rule_id -> suppressed_at

        # Prometheus metrics
        if PROM_AVAILABLE:
            self._prom_fp_rate = Gauge(
                "web3_xdr_rule_fp_rate",
                "Current FP rate per rule (rolling window)",
                ["rule_id"],
            )
            self._prom_feedback_total = Counter(
                "web3_xdr_rule_feedback_total",
                "Total feedback events per rule",
                ["rule_id", "verdict"],
            )
            self._prom_suppressed = Gauge(
                "web3_xdr_rule_suppressed",
                "Whether rule is currently suppressed (1) or active (0)",
                ["rule_id"],
            )
        else:
            self._prom_fp_rate = None
            self._prom_feedback_total = None
            self._prom_suppressed = None

        logger.info(
            "feedback_loop_initialized",
            window_hours=self._window_hours,
            fp_threshold=self._fp_threshold,
            min_samples=self._min_samples,
            auto_disable_fp=self._auto_disable_fp,
        )

    def record_feedback(self, rule_id: str, is_tp: bool):
        """Record a TP or FP verdict for a rule."""
        now = datetime.now(timezone.utc)

        if rule_id not in self._stats:
            self._stats[rule_id] = RuleStats(rule_id=rule_id)

        stats = self._stats[rule_id]
        if is_tp:
            stats.tp_timestamps.append(now)
        else:
            stats.fp_timestamps.append(now)

        # Update Prometheus
        if self._prom_feedback_total:
            verdict = "tp" if is_tp else "fp"
            self._prom_feedback_total.labels(rule_id=rule_id, verdict=verdict).inc()

        logger.debug(
            "feedback_recorded",
            rule_id=rule_id,
            verdict="TP" if is_tp else "FP",
            running_fp_rate=f"{stats.fp_rate:.1%}",
            total_samples=stats.total,
        )

    def record_bulk_feedback(self, feedbacks: List[Tuple[str, bool]]):
        """Record multiple feedback entries at once."""
        for rule_id, is_tp in feedbacks:
            self.record_feedback(rule_id, is_tp)

    def is_suppressed(self, rule_id: str) -> bool:
        """Check if a rule is currently suppressed by the feedback loop."""
        if rule_id in self._suppressed_rules:
            suppressed_at = self._suppressed_rules[rule_id]
            # Check if cooldown has expired — if so, unsuppress for re-evaluation
            if datetime.now(timezone.utc) - suppressed_at > self._cooldown:
                del self._suppressed_rules[rule_id]
                if rule_id in self._stats:
                    self._stats[rule_id].suppressed = False
                if self._prom_suppressed:
                    self._prom_suppressed.labels(rule_id=rule_id).set(0)
                logger.info("rule_unsuppressed_cooldown_expired", rule_id=rule_id)
                return False
            return True
        return False

    def evaluate_rules(self) -> List[Tuple[str, str, float]]:
        """
        Evaluate all tracked rules and return actions taken.

        Returns list of (rule_id, action, fp_rate) where action is:
            - "suppressed": temporarily suppressed (FP rate > threshold)
            - "auto_disabled": permanently disabled (FP rate > auto_disable threshold)
            - "unsuppressed": previously suppressed but now below threshold
            - "healthy": no action needed
        """
        actions = []
        now = datetime.now(timezone.utc)

        for rule_id, stats in list(self._stats.items()):
            # Prune old data
            stats.prune(self._window)

            fp_rate = stats.fp_rate

            # Update Prometheus gauge
            if self._prom_fp_rate:
                self._prom_fp_rate.labels(rule_id=rule_id).set(fp_rate)

            # Skip if not enough samples
            if stats.total < self._min_samples:
                continue

            # Auto-disable: extreme FP rate
            if fp_rate >= self._auto_disable_fp and not stats.auto_disabled:
                stats.auto_disabled = True
                stats.auto_disabled_at = now
                self._suppressed_rules[rule_id] = now
                stats.suppressed = True
                stats.suppressed_at = now

                if self._prom_suppressed:
                    self._prom_suppressed.labels(rule_id=rule_id).set(1)

                actions.append((rule_id, "auto_disabled", fp_rate))
                logger.warning(
                    "rule_auto_disabled",
                    rule_id=rule_id,
                    fp_rate=f"{fp_rate:.1%}",
                    fp_count=stats.fp_count,
                    tp_count=stats.tp_count,
                    window_hours=self._window_hours,
                )

            # Suppress: high FP rate
            elif fp_rate >= self._fp_threshold and rule_id not in self._suppressed_rules:
                self._suppressed_rules[rule_id] = now
                stats.suppressed = True
                stats.suppressed_at = now

                if self._prom_suppressed:
                    self._prom_suppressed.labels(rule_id=rule_id).set(1)

                actions.append((rule_id, "suppressed", fp_rate))
                logger.warning(
                    "rule_suppressed",
                    rule_id=rule_id,
                    fp_rate=f"{fp_rate:.1%}",
                    fp_count=stats.fp_count,
                    tp_count=stats.tp_count,
                )

            # Unsuppress: FP rate dropped below threshold
            elif fp_rate < self._fp_threshold and rule_id in self._suppressed_rules:
                if not stats.auto_disabled:
                    del self._suppressed_rules[rule_id]
                    stats.suppressed = False

                    if self._prom_suppressed:
                        self._prom_suppressed.labels(rule_id=rule_id).set(0)

                    actions.append((rule_id, "unsuppressed", fp_rate))
                    logger.info(
                        "rule_unsuppressed",
                        rule_id=rule_id,
                        fp_rate=f"{fp_rate:.1%}",
                    )

            else:
                actions.append((rule_id, "healthy", fp_rate))

        return actions

    def get_rule_stats(self, rule_id: str) -> Optional[Dict]:
        """Get current stats for a specific rule."""
        if rule_id not in self._stats:
            return None
        stats = self._stats[rule_id]
        stats.prune(self._window)
        return {
            "rule_id": rule_id,
            "tp_count": stats.tp_count,
            "fp_count": stats.fp_count,
            "total": stats.total,
            "fp_rate": round(stats.fp_rate, 4),
            "suppressed": stats.suppressed,
            "auto_disabled": stats.auto_disabled,
            "window_hours": self._window_hours,
        }

    def get_all_stats(self) -> List[Dict]:
        """Get stats for all tracked rules, sorted by FP rate descending."""
        results = []
        for rule_id in self._stats:
            stat = self.get_rule_stats(rule_id)
            if stat and stat["total"] > 0:
                results.append(stat)
        return sorted(results, key=lambda x: x["fp_rate"], reverse=True)

    def load_from_db(self, db_cursor):
        """
        Bootstrap feedback loop from historical incident data.

        Reads incident status (RESOLVED=TP, FALSE_POSITIVE=FP) and
        populates the rolling window. Call this on startup.
        """
        window_cutoff = datetime.now(timezone.utc) - self._window

        db_cursor.execute("""
            SELECT rule_ids, status, updated_at
            FROM incidents
            WHERE status IN ('RESOLVED', 'FALSE_POSITIVE', 'ACKNOWLEDGED')
            AND updated_at > %s
        """, (window_cutoff,))

        loaded = 0
        for row in db_cursor.fetchall():
            rule_ids = row[0] or []
            status = row[1]
            ts = row[2]

            is_tp = status in ('RESOLVED', 'ACKNOWLEDGED')

            for rule_id in rule_ids:
                if rule_id not in self._stats:
                    self._stats[rule_id] = RuleStats(rule_id=rule_id)
                stats = self._stats[rule_id]
                if is_tp:
                    stats.tp_timestamps.append(ts)
                else:
                    stats.fp_timestamps.append(ts)
                loaded += 1

        # Run initial evaluation
        actions = self.evaluate_rules()

        logger.info(
            "feedback_loop_loaded_from_db",
            feedbacks_loaded=loaded,
            rules_tracked=len(self._stats),
            rules_suppressed=len(self._suppressed_rules),
            actions=[f"{a[0]}:{a[1]}" for a in actions if a[1] != "healthy"],
        )

        return loaded


# Singleton
_feedback_loop: Optional[FeedbackLoop] = None


def get_feedback_loop() -> FeedbackLoop:
    """Get or create the global feedback loop instance."""
    global _feedback_loop
    if _feedback_loop is None:
        _feedback_loop = FeedbackLoop()
    return _feedback_loop
