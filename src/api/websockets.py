"""
WebSocket Feed for Live Threat Dashboard
========================================

Provides real-time WebSocket feed for the "War Room" visualization dashboard.
Connects to Redis Pub/Sub to broadcast runtime intents, threats, and incidents.
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, Set
import structlog
import redis.asyncio as aioredis

from fastapi import WebSocket, WebSocketDisconnect
from starlette.websockets import WebSocketState

from ..config.settings import settings

logger = structlog.get_logger(__name__)


class ConnectionManager:
    """Manages WebSocket connections and Redis Pub/Sub subscriptions."""
    
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()
        self.redis_client: aioredis.Redis = None
        self.pubsub = None
        self._redis_task: asyncio.Task = None
        self._running = False
    
    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info("websocket_client_connected", client_count=len(self.active_connections))
        
        # Initialize Redis if first connection
        if not self._running and len(self.active_connections) == 1:
            await self._start_redis_subscription()
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection."""
        self.active_connections.discard(websocket)
        logger.info("websocket_client_disconnected", client_count=len(self.active_connections))
        
        # Stop Redis subscription if no connections
        if len(self.active_connections) == 0:
            await self._stop_redis_subscription()
    
    async def _start_redis_subscription(self):
        """Start Redis Pub/Sub subscription."""
        try:
            redis_url = settings.REDIS_URL or "redis://localhost:6379/0"
            self.redis_client = aioredis.from_url(redis_url, decode_responses=True)
            self.pubsub = self.redis_client.pubsub()
            
            # Subscribe to runtime intents channel
            await self.pubsub.subscribe("runtime_intents")
            logger.info("redis_pubsub_subscribed", channel="runtime_intents")
            
            self._running = True
            self._redis_task = asyncio.create_task(self._redis_listener())
        
        except Exception as e:
            logger.error("redis_subscription_failed", error=str(e))
            self._running = False
    
    async def _stop_redis_subscription(self):
        """Stop Redis Pub/Sub subscription."""
        if self._redis_task:
            self._redis_task.cancel()
            try:
                await self._redis_task
            except asyncio.CancelledError:
                pass
        
        if self.pubsub:
            await self.pubsub.unsubscribe("runtime_intents")
            await self.pubsub.close()
        
        if self.redis_client:
            await self.redis_client.close()
        
        self._running = False
        logger.info("redis_pubsub_unsubscribed")
    
    async def _redis_listener(self):
        """Listen to Redis Pub/Sub messages and broadcast to WebSocket clients."""
        while self._running:
            try:
                message = await self.pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                
                if message and message["type"] == "message":
                    try:
                        data = json.loads(message["data"])
                        await self.broadcast(data)
                    except json.JSONDecodeError as e:
                        logger.warning("invalid_json_from_redis", error=str(e))
                    except Exception as e:
                        logger.error("broadcast_error", error=str(e))
            
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error("redis_listener_error", error=str(e))
                await asyncio.sleep(1.0)
    
    async def broadcast(self, message: Dict):
        """Broadcast a message to all connected WebSocket clients."""
        if not self.active_connections:
            return
        
        # Format message for frontend
        formatted_message = self._format_message(message)
        message_json = json.dumps(formatted_message)
        
        # Send to all connected clients
        disconnected = set()
        for connection in self.active_connections:
            try:
                if connection.client_state == WebSocketState.CONNECTED:
                    await connection.send_text(message_json)
                else:
                    disconnected.add(connection)
            except Exception as e:
                logger.warning("websocket_send_failed", error=str(e))
                disconnected.add(connection)
        
        # Remove disconnected clients
        for conn in disconnected:
            await self.disconnect(conn)
    
    def _format_message(self, message: Dict) -> Dict:
        """
        Format message for frontend consumption.
        
        Expected input from Redis:
        {
            "type": "intent" | "simulation" | "threat" | "incident",
            "chain_id": "ethereum",
            "tx_hash": "0x...",
            "contract_address": "0x...",
            "risk_score": 0.85,
            "status": "scanning" | "simulating" | "safe" | "malicious",
            "timestamp": 1234567890,
            ...
        }
        
        Output format:
        {
            "type": "SCAN" | "THREAT",
            "timestamp": 1234567890,
            "source_chain": "ethereum",
            "tx_hash": "0x...",
            "contract": "0x...",
            "risk_score": 0.85,
            "status": "Safe" | "Simulating..." | "MALICIOUS"
        }
        """
        msg_type = message.get("type", "intent")
        
        # Map backend types to frontend types
        if msg_type in ["threat", "incident", "predicted_incident"]:
            frontend_type = "THREAT"
        else:
            frontend_type = "SCAN"
        
        # Map status
        status_map = {
            "scanning": "Scanning...",
            "simulating": "Simulating...",
            "safe": "Safe",
            "malicious": "MALICIOUS",
            "confirmed": "MALICIOUS",
            "violated": "MALICIOUS"
        }
        status = status_map.get(message.get("status", "scanning"), "Scanning...")
        
        # Extract risk score
        risk_score = message.get("risk_score", 0.0)
        if risk_score is None:
            risk_score = 0.0
        
        return {
            "type": frontend_type,
            "timestamp": message.get("timestamp", int(datetime.now(timezone.utc).timestamp())),
            "source_chain": message.get("chain_id", message.get("source_chain", "unknown")),
            "tx_hash": message.get("tx_hash", ""),
            "contract": message.get("contract_address", message.get("to_address", "")),
            "risk_score": float(risk_score),
            "status": status,
            "details": message.get("details", {}),
            "protocol": message.get("protocol_id", ""),
        }


# Global connection manager instance
manager = ConnectionManager()


async def websocket_feed(websocket: WebSocket):
    """
    WebSocket endpoint for live threat feed.
    
    Endpoint: WS /ws/feed
    
    Clients connect and receive real-time updates about:
    - Scanned intents
    - Simulation results
    - Detected threats
    - Predicted incidents
    """
    await manager.connect(websocket)
    
    try:
        # Send welcome message
        await websocket.send_json({
            "type": "CONNECTED",
            "message": "Connected to Sentinel3 Live Threat Feed",
            "timestamp": int(datetime.now(timezone.utc).timestamp())
        })
        
        # Keep connection alive
        while True:
            # Wait for ping or close
            try:
                data = await websocket.receive_text()
                # Echo back (or handle client messages if needed)
                if data == "ping":
                    await websocket.send_json({"type": "pong"})
            except WebSocketDisconnect:
                break
    
    except WebSocketDisconnect:
        logger.info("websocket_client_disconnected_normally")
    except Exception as e:
        logger.error("websocket_error", error=str(e))
    finally:
        await manager.disconnect(websocket)

