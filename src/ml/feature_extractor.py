"""
ML Feature Extractor
====================

Extracts features from blockchain events for ML model input.
Features are derived from:
1. YAML rule knowledge (what rules care about)
2. Graph context (relationships and associations)
3. Temporal patterns (time-based features)
4. Domain knowledge (Web3-specific features)
"""

import math
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Tuple
from decimal import Decimal
from dataclasses import dataclass, field
import numpy as np
import structlog

logger = structlog.get_logger(__name__)


@dataclass
class FeatureVector:
    """Feature vector for ML model input."""
    
    # Basic features
    basic: Dict[str, float] = field(default_factory=dict)
    
    # Event type features (one-hot encoded)
    event_type: Dict[str, float] = field(default_factory=dict)
    
    # Amount features
    amount: Dict[str, float] = field(default_factory=dict)
    
    # Address features
    address: Dict[str, float] = field(default_factory=dict)
    
    # Temporal features
    temporal: Dict[str, float] = field(default_factory=dict)
    
    # Graph features (from Neo4j)
    graph: Dict[str, float] = field(default_factory=dict)
    
    # Context features
    context: Dict[str, float] = field(default_factory=dict)
    
    def to_array(self, feature_order: List[str]) -> np.ndarray:
        """Convert to numpy array in specified feature order."""
        all_features = {
            **self.basic,
            **self.event_type,
            **self.amount,
            **self.address,
            **self.temporal,
            **self.graph,
            **self.context
        }
        return np.array([all_features.get(f, 0.0) for f in feature_order])
    
    def to_dict(self) -> Dict[str, float]:
        """Convert to flat dictionary."""
        return {
            **self.basic,
            **self.event_type,
            **self.amount,
            **self.address,
            **self.temporal,
            **self.graph,
            **self.context
        }


class FeatureExtractor:
    """
    Extracts ML features from blockchain events.
    
    Feature Categories:
    1. Basic: chain_id, block_number, log_index
    2. Event Type: one-hot encoded event types
    3. Amount: amount, amount_usd, log-scaled versions
    4. Address: from/to address properties
    5. Temporal: hour, day, is_weekend, etc.
    6. Graph: risk scores, connection counts
    7. Context: protocol-specific features
    """
    
    # Known event types for one-hot encoding
    EVENT_TYPES = [
        "Transfer", "Swap", "FlashLoan", "Liquidation", "Deposit", "Withdraw",
        "Borrow", "Repay", "Approval", "AdminAction", "OwnershipTransferred",
        "Paused", "Unpaused", "Upgrade", "Bridge", "Mint", "Burn", "Stake",
        "Unstake", "Claim", "Vote", "Propose", "Execute", "Unknown"
    ]
    
    # Known chains for encoding
    CHAINS = [
        "ethereum", "polygon", "arbitrum", "optimism", "bsc", "avalanche", "base"
    ]
    
    # Known protocols
    PROTOCOLS = [
        "uniswap", "aave", "compound", "curve", "makerdao", "lido", "chainlink",
        "balancer", "sushiswap", "yearn", "convex", "gmx", "unknown"
    ]
    
    def __init__(
        self,
        feature_blueprint: Optional[Dict[str, Any]] = None,
        graph_connection: Optional[Any] = None
    ):
        """
        Initialize feature extractor.
        
        Args:
            feature_blueprint: Blueprint from YAMLToMLConverter
            graph_connection: Neo4j connection for graph features
        """
        self.blueprint = feature_blueprint or {}
        self.graph_conn = graph_connection
        
        # Cache for address properties
        self._address_cache: Dict[str, Dict[str, Any]] = {}
        
        # Feature order for consistent array output
        self._feature_order: Optional[List[str]] = None
    
    def extract_features(
        self,
        event: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> FeatureVector:
        """
        Extract all features from an event.
        
        Args:
            event: Security event dictionary
            context: Optional context (protocol stats, etc.)
            
        Returns:
            FeatureVector with all extracted features
        """
        features = FeatureVector()
        
        # Extract each feature category
        features.basic = self._extract_basic_features(event)
        features.event_type = self._extract_event_type_features(event)
        features.amount = self._extract_amount_features(event, context)
        features.address = self._extract_address_features(event)
        features.temporal = self._extract_temporal_features(event)
        features.context = self._extract_context_features(event, context)
        
        # Graph features require async - will be added separately
        # features.graph = await self._extract_graph_features(event)
        
        return features
    
    async def extract_features_with_graph(
        self,
        event: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> FeatureVector:
        """
        Extract all features including graph features (async).
        
        Args:
            event: Security event dictionary
            context: Optional context
            
        Returns:
            FeatureVector with all features including graph
        """
        features = self.extract_features(event, context)
        
        if self.graph_conn:
            features.graph = await self._extract_graph_features(event)
        
        return features
    
    def _extract_basic_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract basic features."""
        features = {}
        
        # Chain encoding
        chain_id = event.get("chain_id", "ethereum").lower()
        for chain in self.CHAINS:
            features[f"chain_{chain}"] = 1.0 if chain_id == chain else 0.0
        
        # Block number (normalized)
        block_number = event.get("block_number", 0)
        features["block_number_log"] = math.log1p(block_number)
        
        # Log index
        log_index = event.get("log_index", 0)
        features["log_index"] = float(log_index)
        
        return features
    
    def _extract_event_type_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract one-hot encoded event type features."""
        features = {}
        
        event_type = event.get("event_type", "Unknown")
        if hasattr(event_type, "value"):
            event_type = event_type.value
        event_type = str(event_type)
        
        # One-hot encode
        for et in self.EVENT_TYPES:
            features[f"event_type_{et.lower()}"] = 1.0 if event_type.lower() == et.lower() else 0.0
        
        return features
    
    def _extract_amount_features(
        self,
        event: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """Extract amount-related features."""
        features = {}
        
        # Raw amount
        amount = float(event.get("amount", 0) or 0)
        features["amount"] = amount
        features["amount_log"] = math.log1p(amount)
        
        # USD amount
        amount_usd = float(event.get("amount_usd", 0) or 0)
        features["amount_usd"] = amount_usd
        features["amount_usd_log"] = math.log1p(amount_usd)
        
        # Threshold features (from YAML knowledge)
        features["amount_usd_gt_1k"] = 1.0 if amount_usd > 1000 else 0.0
        features["amount_usd_gt_10k"] = 1.0 if amount_usd > 10000 else 0.0
        features["amount_usd_gt_100k"] = 1.0 if amount_usd > 100000 else 0.0
        features["amount_usd_gt_1m"] = 1.0 if amount_usd > 1000000 else 0.0
        features["amount_usd_gt_10m"] = 1.0 if amount_usd > 10000000 else 0.0
        
        # Context-relative features
        if context:
            protocol_avg = context.get("protocol_avg_tx_usd", 10000)
            if protocol_avg > 0:
                features["amount_vs_protocol_avg"] = amount_usd / protocol_avg
            
            protocol_max = context.get("protocol_max_tx_usd", 1000000)
            if protocol_max > 0:
                features["amount_vs_protocol_max"] = amount_usd / protocol_max
        
        return features
    
    def _extract_address_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract address-related features."""
        features = {}
        
        from_addr = event.get("source_address", "") or ""
        to_addr = event.get("dest_address", "") or ""
        contract_addr = event.get("contract_address", "") or ""
        
        # Address presence
        features["has_from_address"] = 1.0 if from_addr else 0.0
        features["has_to_address"] = 1.0 if to_addr else 0.0
        
        # Zero address checks
        zero_addr = "0x" + "0" * 40
        features["from_is_zero"] = 1.0 if from_addr.lower() == zero_addr else 0.0
        features["to_is_zero"] = 1.0 if to_addr.lower() == zero_addr else 0.0
        
        # Self-transfer
        features["is_self_transfer"] = 1.0 if from_addr.lower() == to_addr.lower() and from_addr else 0.0
        
        # Contract interaction
        features["is_contract_interaction"] = 1.0 if contract_addr else 0.0
        
        # Check cached address properties
        if from_addr.lower() in self._address_cache:
            cached = self._address_cache[from_addr.lower()]
            features["from_is_exchange"] = 1.0 if cached.get("is_exchange") else 0.0
            features["from_is_mixer"] = 1.0 if cached.get("is_mixer") else 0.0
            features["from_is_hacker"] = 1.0 if cached.get("is_hacker") else 0.0
            features["from_risk_score"] = cached.get("risk_score", 0.0) / 100.0
        
        if to_addr.lower() in self._address_cache:
            cached = self._address_cache[to_addr.lower()]
            features["to_is_exchange"] = 1.0 if cached.get("is_exchange") else 0.0
            features["to_is_mixer"] = 1.0 if cached.get("is_mixer") else 0.0
            features["to_is_hacker"] = 1.0 if cached.get("is_hacker") else 0.0
            features["to_risk_score"] = cached.get("risk_score", 0.0) / 100.0
        
        return features
    
    def _extract_temporal_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract time-based features."""
        features = {}
        
        timestamp = event.get("block_timestamp")
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
                except:
                    timestamp = datetime.now(timezone.utc)
            elif not isinstance(timestamp, datetime):
                timestamp = datetime.now(timezone.utc)
        else:
            timestamp = datetime.now(timezone.utc)
        
        # Hour of day (cyclical encoding)
        hour = timestamp.hour
        features["hour_sin"] = math.sin(2 * math.pi * hour / 24)
        features["hour_cos"] = math.cos(2 * math.pi * hour / 24)
        
        # Day of week (cyclical encoding)
        day = timestamp.weekday()
        features["day_sin"] = math.sin(2 * math.pi * day / 7)
        features["day_cos"] = math.cos(2 * math.pi * day / 7)
        
        # Binary features
        features["is_weekend"] = 1.0 if day >= 5 else 0.0
        features["is_night"] = 1.0 if hour < 6 or hour > 22 else 0.0
        features["is_business_hours"] = 1.0 if 9 <= hour <= 17 and day < 5 else 0.0
        
        return features
    
    def _extract_context_features(
        self,
        event: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, float]:
        """Extract context-based features."""
        features = {}
        
        # Protocol encoding
        raw_event = event.get("raw_event", {}) or {}
        protocol = raw_event.get("protocol", "unknown").lower()
        
        for p in self.PROTOCOLS:
            features[f"protocol_{p}"] = 1.0 if protocol == p else 0.0
        
        # Severity encoding (if available)
        severity = event.get("severity", "low")
        if hasattr(severity, "value"):
            severity = severity.value
        severity = str(severity).lower()
        
        severity_map = {"info": 0.0, "low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        features["severity_score"] = severity_map.get(severity, 0.25)
        
        # Context features
        if context:
            features["protocol_tvl_log"] = math.log1p(context.get("protocol_tvl", 0))
            features["protocol_tx_count_24h"] = float(context.get("tx_count_24h", 0))
            features["protocol_unique_users_24h"] = float(context.get("unique_users_24h", 0))
        
        return features
    
    async def _extract_graph_features(self, event: Dict[str, Any]) -> Dict[str, float]:
        """Extract graph-based features from Neo4j."""
        features = {}
        
        if not self.graph_conn:
            return features
        
        from_addr = event.get("source_address", "")
        to_addr = event.get("dest_address", "")
        chain_id = event.get("chain_id", "ethereum")
        
        # Query graph for from_address
        if from_addr:
            try:
                query = """
                MATCH (w:Wallet {address: $address, chain_id: $chain_id})
                OPTIONAL MATCH (w)-[*1..3]-(hacker:Hacker)
                OPTIONAL MATCH (w)-[*1..2]-(mixer:Mixer)
                OPTIONAL MATCH (w)-[r:TRANSFERS_TO]->()
                
                RETURN
                    w.risk_score AS risk_score,
                    w.transaction_count AS tx_count,
                    count(DISTINCT hacker) AS hacker_connections,
                    count(DISTINCT mixer) AS mixer_connections,
                    count(r) AS outgoing_transfers
                """
                
                results = await self.graph_conn.query(query, {
                    "address": from_addr.lower(),
                    "chain_id": chain_id
                })
                
                if results:
                    r = results[0]
                    features["from_graph_risk_score"] = (r.get("risk_score") or 0) / 100.0
                    features["from_graph_tx_count_log"] = math.log1p(r.get("tx_count") or 0)
                    features["from_graph_hacker_connections"] = float(r.get("hacker_connections") or 0)
                    features["from_graph_mixer_connections"] = float(r.get("mixer_connections") or 0)
                    features["from_graph_outgoing_transfers_log"] = math.log1p(r.get("outgoing_transfers") or 0)
            except Exception as e:
                logger.debug("graph_feature_error", address=from_addr[:10], error=str(e))
        
        # Query graph for to_address
        if to_addr:
            try:
                query = """
                MATCH (w:Wallet {address: $address, chain_id: $chain_id})
                RETURN
                    w.risk_score AS risk_score,
                    w.is_mixer AS is_mixer,
                    w.is_hacker AS is_hacker
                """
                
                results = await self.graph_conn.query(query, {
                    "address": to_addr.lower(),
                    "chain_id": chain_id
                })
                
                if results:
                    r = results[0]
                    features["to_graph_risk_score"] = (r.get("risk_score") or 0) / 100.0
                    features["to_graph_is_mixer"] = 1.0 if r.get("is_mixer") else 0.0
                    features["to_graph_is_hacker"] = 1.0 if r.get("is_hacker") else 0.0
            except Exception as e:
                logger.debug("graph_feature_error", address=to_addr[:10], error=str(e))
        
        return features
    
    def get_feature_names(self) -> List[str]:
        """Get ordered list of all feature names."""
        if self._feature_order:
            return self._feature_order
        
        # Generate feature names from a sample extraction
        sample_event = {
            "chain_id": "ethereum",
            "block_number": 1000000,
            "log_index": 0,
            "event_type": "Transfer",
            "amount": 1.0,
            "amount_usd": 1000.0,
            "source_address": "0x" + "1" * 40,
            "dest_address": "0x" + "2" * 40,
            "contract_address": "0x" + "3" * 40,
            "block_timestamp": datetime.now(timezone.utc),
            "severity": "low"
        }
        
        features = self.extract_features(sample_event)
        self._feature_order = sorted(features.to_dict().keys())
        
        return self._feature_order
    
    def update_address_cache(self, address: str, properties: Dict[str, Any]):
        """Update the address property cache."""
        self._address_cache[address.lower()] = properties
    
    def batch_extract(
        self,
        events: List[Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None
    ) -> np.ndarray:
        """
        Extract features for multiple events.
        
        Args:
            events: List of events
            context: Optional shared context
            
        Returns:
            2D numpy array of shape (n_events, n_features)
        """
        feature_names = self.get_feature_names()
        
        feature_matrix = []
        for event in events:
            features = self.extract_features(event, context)
            feature_matrix.append(features.to_array(feature_names))
        
        return np.array(feature_matrix)
