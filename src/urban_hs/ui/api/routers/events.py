"""Real-time event streaming over WebSocket for Urban Hack Sentinel."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from urban_hs.core.event_bus import Event, EventHandler, get_event_bus

router = APIRouter()

logger = logging.getLogger(__name__)


class WebSocketConnectionManager:
    """Track active WebSocket connections for broadcast."""

    def __init__(self) -> None:
        self._active: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._active.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._active.discard(websocket)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        if not self._active:
            return
        payload = json.dumps(message)
        await asyncio.gather(
            *(self._send(ws, payload) for ws in list(self._active)),
            return_exceptions=True,
        )

    async def _send(self, websocket: WebSocket, payload: str) -> None:
        try:
            await websocket.send_text(payload)
        except Exception:
            self.disconnect(websocket)


manager = WebSocketConnectionManager()


class WebSocketEventHandler(EventHandler):
    """Forward selected events to connected WebSocket clients."""

    @property
    def event_types(self) -> Set[str]:
        return {"*"}

    async def handle(self, event: Event) -> None:
        await manager.broadcast(
            {
                "type": event.type,
                "payload": event.payload,
                "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "correlation_id": event.correlation_id,
                "source": event.source,
            }
        )


@router.websocket("/events")
async def websocket_events(websocket: WebSocket) -> None:
    await manager.connect(websocket)
    bus = get_event_bus()
    bus.subscribe(WebSocketEventHandler())
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(websocket)
