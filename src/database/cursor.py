"""
Cursor Pagination Utilities
"""

import base64
import json
from datetime import datetime
from typing import Optional, Tuple
from uuid import UUID


def encode_cursor(block_timestamp: datetime, event_id: str) -> str:
    """
    Encode cursor from timestamp and event ID.
    
    Cursor format: base64(json({timestamp, id}))
    """
    cursor_data = {
        "timestamp": block_timestamp.isoformat(),
        "id": str(event_id)
    }
    cursor_json = json.dumps(cursor_data)
    cursor_bytes = cursor_json.encode('utf-8')
    cursor_b64 = base64.b64encode(cursor_bytes).decode('utf-8')
    return cursor_b64


def decode_cursor(cursor: str) -> Optional[Tuple[datetime, str]]:
    """
    Decode cursor to timestamp and event ID.
    
    Returns: (block_timestamp, event_id) or None if invalid
    """
    try:
        cursor_bytes = base64.b64decode(cursor.encode('utf-8'))
        cursor_json = cursor_bytes.decode('utf-8')
        cursor_data = json.loads(cursor_json)
        
        timestamp_str = cursor_data.get("timestamp")
        event_id = cursor_data.get("id")
        
        if not timestamp_str or not event_id:
            return None
        
        timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
        return (timestamp, event_id)
    except Exception:
        return None
