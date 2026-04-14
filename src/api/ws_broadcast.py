"""
Helper functions to broadcast events from anywhere in the codebase.

These are fire-and-forget wrappers around the WebSocket manager.
Import failures are silently ignored so callers never break if
the WebSocket module is unavailable.
"""
import logging

logger = logging.getLogger(__name__)


async def broadcast_incident(incident_data: dict):
    """Broadcast a new/updated incident to WebSocket clients."""
    try:
        from src.api.websocket_routes import manager
        await manager.broadcast_incident(incident_data)
    except Exception as e:
        logger.debug("WS broadcast (incident) failed: %s", e)


async def broadcast_event(event_data: dict):
    """Broadcast a new security event."""
    try:
        from src.api.websocket_routes import manager
        await manager.broadcast_event(event_data)
    except Exception as e:
        logger.debug("WS broadcast (event) failed: %s", e)


async def broadcast_alert(alert_data: dict):
    """Broadcast an alert."""
    try:
        from src.api.websocket_routes import manager
        await manager.broadcast_alert(alert_data)
    except Exception as e:
        logger.debug("WS broadcast (alert) failed: %s", e)


async def broadcast_guardian_action(action_data: dict):
    """Broadcast guardian action updates."""
    try:
        from src.api.websocket_routes import manager
        await manager.broadcast_guardian(action_data)
    except Exception as e:
        logger.debug("WS broadcast (guardian) failed: %s", e)


async def broadcast_stats(stats_data: dict):
    """Broadcast stats updates."""
    try:
        from src.api.websocket_routes import manager
        await manager.broadcast_stats(stats_data)
    except Exception as e:
        logger.debug("WS broadcast (stats) failed: %s", e)
