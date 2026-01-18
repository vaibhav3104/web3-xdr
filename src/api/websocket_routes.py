"""
WebSocket Routes for Real-time Event Streaming
Provides live updates for events, incidents, and alerts
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List, Set
import asyncio
import json
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)

router = APIRouter(tags=["WebSocket"])

# Connection manager for WebSocket clients
class ConnectionManager:
    """Manages WebSocket connections and broadcasts"""
    
    def __init__(self):
        # Active connections by channel
        self.active_connections: Dict[str, Set[WebSocket]] = {
            "events": set(),
            "incidents": set(),
            "alerts": set(),
            "stats": set(),
            "all": set(),  # Receives everything
        }
        self._lock = asyncio.Lock()
    
    async def connect(self, websocket: WebSocket, channel: str = "all"):
        """Accept and register a new connection"""
        await websocket.accept()
        async with self._lock:
            if channel not in self.active_connections:
                self.active_connections[channel] = set()
            self.active_connections[channel].add(websocket)
            self.active_connections["all"].add(websocket)
        
        logger.info("websocket_connected", channel=channel, total_connections=self.total_connections)
        
        # Send welcome message
        await websocket.send_json({
            "type": "connected",
            "channel": channel,
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Connected to Sentinel3 {channel} stream"
        })
    
    async def disconnect(self, websocket: WebSocket):
        """Remove a connection from all channels"""
        async with self._lock:
            for channel in self.active_connections.values():
                channel.discard(websocket)
        logger.info("websocket_disconnected", total_connections=self.total_connections)
    
    async def broadcast(self, message: dict, channel: str = "all"):
        """Broadcast message to all connections in a channel"""
        if channel not in self.active_connections:
            return
        
        message["timestamp"] = datetime.utcnow().isoformat()
        
        disconnected = set()
        for connection in self.active_connections[channel]:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.add(connection)
        
        # Clean up disconnected clients
        if disconnected:
            async with self._lock:
                for conn in disconnected:
                    for ch in self.active_connections.values():
                        ch.discard(conn)
    
    async def broadcast_event(self, event: dict):
        """Broadcast a new event"""
        await self.broadcast({
            "type": "event",
            "data": event
        }, "events")
    
    async def broadcast_incident(self, incident: dict):
        """Broadcast a new or updated incident"""
        await self.broadcast({
            "type": "incident",
            "data": incident
        }, "incidents")
    
    async def broadcast_alert(self, alert: dict):
        """Broadcast an ML alert"""
        await self.broadcast({
            "type": "alert",
            "data": alert
        }, "alerts")
    
    async def broadcast_stats(self, stats: dict):
        """Broadcast updated stats"""
        await self.broadcast({
            "type": "stats",
            "data": stats
        }, "stats")
    
    @property
    def total_connections(self) -> int:
        """Total unique connections across all channels"""
        return len(self.active_connections.get("all", set()))


# Global connection manager
manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """
    Main WebSocket endpoint for real-time updates
    
    Receives all event types: events, incidents, alerts, stats
    """
    await manager.connect(websocket, "all")
    try:
        while True:
            # Keep connection alive and handle client messages
            data = await websocket.receive_text()
            
            try:
                message = json.loads(data)
                
                # Handle subscription changes
                if message.get("action") == "subscribe":
                    channel = message.get("channel", "all")
                    async with manager._lock:
                        if channel in manager.active_connections:
                            manager.active_connections[channel].add(websocket)
                    await websocket.send_json({
                        "type": "subscribed",
                        "channel": channel
                    })
                
                elif message.get("action") == "unsubscribe":
                    channel = message.get("channel")
                    if channel and channel != "all":
                        async with manager._lock:
                            manager.active_connections.get(channel, set()).discard(websocket)
                        await websocket.send_json({
                            "type": "unsubscribed",
                            "channel": channel
                        })
                
                elif message.get("action") == "ping":
                    await websocket.send_json({
                        "type": "pong",
                        "timestamp": datetime.utcnow().isoformat()
                    })
                    
            except json.JSONDecodeError:
                await websocket.send_json({
                    "type": "error",
                    "message": "Invalid JSON"
                })
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@router.websocket("/ws/events")
async def events_websocket(websocket: WebSocket):
    """WebSocket endpoint for event stream only"""
    await manager.connect(websocket, "events")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@router.websocket("/ws/incidents")
async def incidents_websocket(websocket: WebSocket):
    """WebSocket endpoint for incident stream only"""
    await manager.connect(websocket, "incidents")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@router.websocket("/ws/alerts")
async def alerts_websocket(websocket: WebSocket):
    """WebSocket endpoint for ML alerts stream only"""
    await manager.connect(websocket, "alerts")
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        await manager.disconnect(websocket)


@router.get("/ws/status")
async def websocket_status():
    """Get WebSocket connection status"""
    return {
        "total_connections": manager.total_connections,
        "connections_by_channel": {
            channel: len(connections)
            for channel, connections in manager.active_connections.items()
        }
    }


# Export manager for use by other modules
def get_ws_manager() -> ConnectionManager:
    """Get the global WebSocket connection manager"""
    return manager


# Helper functions to broadcast from other parts of the app
async def broadcast_new_event(event: dict):
    """Broadcast a new event to all WebSocket clients"""
    await manager.broadcast_event(event)


async def broadcast_new_incident(incident: dict):
    """Broadcast a new incident to all WebSocket clients"""
    await manager.broadcast_incident(incident)


async def broadcast_new_alert(alert: dict):
    """Broadcast a new ML alert to all WebSocket clients"""
    await manager.broadcast_alert(alert)


async def broadcast_stats_update(stats: dict):
    """Broadcast stats update to all WebSocket clients"""
    await manager.broadcast_stats(stats)
