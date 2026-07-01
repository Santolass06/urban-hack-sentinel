"""Real-time event streaming over WebSocket for Urban Hack Sentinel."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, Optional, Set

from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status
from jose import JWTError

from urban_hs.core.event_bus import Event, EventHandler, get_event_bus
from urban_hs.ui.api.auth import decode_access_token

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


def _extract_ws_token(websocket: WebSocket, token: Optional[str]) -> Optional[str]:
    """Pull a Bearer token from the Authorization header, falling back to ?token=."""
    auth_header = websocket.headers.get("authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1]
    return token


@router.websocket("/events")
async def websocket_events(
    websocket: WebSocket, token: Optional[str] = Query(default=None)
) -> None:
    bearer = _extract_ws_token(websocket, token)
    if not bearer:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return
    try:
        decode_access_token(bearer)
    except JWTError:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        return

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
