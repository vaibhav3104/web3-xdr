"""
Redis Pub/Sub Publisher for Runtime Intents
============================================

Publishes runtime intents, simulation results, and threats to Redis Pub/Sub
for real-time WebSocket broadcasting to the War Room dashboard.
"""

import json
from datetime import datetime, timezone
from typing import Dict, Optional
import structlog

try:
    import redis.asyncio as aioredis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    aioredis = None

from ..config.settings import settings

logger = structlog.get_logger(__name__)


class RuntimePubSub:
    """Publishes runtime events to Redis Pub/Sub for WebSocket broadcasting."""
    
    def __init__(self):
        self.redis_client: Optional[aioredis.Redis] = None
        self.channel = "runtime_intents"
        self._initialized = False
    
    async def initialize(self):
        """Initialize Redis connection."""
        if not REDIS_AVAILABLE:
            logger.warning("redis_not_available_for_pubsub", message="Redis Pub/Sub disabled")
            return
        
        try:
            redis_url = settings.REDIS_URL or "redis://localhost:6379/0"
            self.redis_client = aioredis.from_url(redis_url, decode_responses=False)
            self._initialized = True
            logger.info("runtime_pubsub_initialized", channel=self.channel)
        except Exception as e:
            logger.error("runtime_pubsub_init_failed", error=str(e))
            self._initialized = False
    
    async def publish_intent(self, chain_id: str, tx_hash: str, contract: str, risk_score: float = 0.0):
        """Publish an intent scan event."""
        if not self._initialized:
            return
        
        message = {
            "type": "intent",
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "contract_address": contract,
            "risk_score": risk_score,
            "status": "scanning",
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }
        
        await self._publish(message)
    
    async def publish_simulation(self, chain_id: str, tx_hash: str, contract: str, risk_score: float, status: str):
        """Publish a simulation result."""
        if not self._initialized:
            return
        
        message = {
            "type": "simulation",
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "contract_address": contract,
            "risk_score": risk_score,
            "status": status,  # "simulating", "safe", "malicious"
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
        }
        
        await self._publish(message)
    
    async def publish_threat(self, chain_id: str, tx_hash: str, contract: str, protocol: str, risk_score: float, details: Dict):
        """Publish a detected threat."""
        if not self._initialized:
            return
        
        message = {
            "type": "threat",
            "chain_id": chain_id,
            "tx_hash": tx_hash,
            "contract_address": contract,
            "protocol_id": protocol,
            "risk_score": risk_score,
            "status": "malicious",
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "details": details,
        }
        
        await self._publish(message)
    
    async def publish_predicted_incident(self, incident: Dict):
        """Publish a predicted incident."""
        if not self._initialized:
            return
        
        message = {
            "type": "predicted_incident",
            "chain_id": incident.get("chain_id", ""),
            "tx_hash": incident.get("tx_hash", ""),
            "contract_address": incident.get("protocol_id", ""),
            "protocol_id": incident.get("protocol_id", ""),
            "risk_score": incident.get("confidence", 0.0),
            "status": "malicious",
            "timestamp": int(datetime.now(timezone.utc).timestamp()),
            "details": {
                "predicted_type": incident.get("predicted_type", ""),
                "severity": incident.get("severity", ""),
                "confidence": incident.get("confidence", 0.0),
            },
        }
        
        await self._publish(message)
    
    async def _publish(self, message: Dict):
        """Internal publish method."""
        try:
            if not self.redis_client:
                return
            
            message_json = json.dumps(message)
            await self.redis_client.publish(self.channel, message_json)
            logger.debug("runtime_pubsub_published", type=message.get("type"), tx_hash=message.get("tx_hash", "")[:16])
        except Exception as e:
            logger.error("runtime_pubsub_publish_failed", error=str(e))
    
    async def close(self):
        """Close Redis connection."""
        if self.redis_client:
            await self.redis_client.close()
            self._initialized = False
            logger.info("runtime_pubsub_closed")


# Global instance
_runtime_pubsub: Optional[RuntimePubSub] = None


async def get_runtime_pubsub() -> RuntimePubSub:
    """Get or create global RuntimePubSub instance."""
    global _runtime_pubsub
    if _runtime_pubsub is None:
        _runtime_pubsub = RuntimePubSub()
        await _runtime_pubsub.initialize()
    return _runtime_pubsub

