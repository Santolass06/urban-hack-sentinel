"""
Urban Hack Sentinel v3 — FastAPI backend (REST + WebSocket).

Entry point::

    uvicorn urban_hs.ui.api.main:run --host 0.0.0.0 --port 8000

The ``run`` helper is registered as a console script in ``pyproject.toml``
(``urban-hs-server``).
"""

from __future__ import annotations

import os
from typing import Any, Dict

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from urban_hs.core import init_core, shutdown_core


app = FastAPI(
    title="Urban Hack Sentinel API",
    description="REST + WebSocket API for wireless/Bluetooth/IoT auditing.",
    version="3.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------
@app.on_event("startup")
async def _startup() -> None:
    await init_core(
        config_file=os.environ.get("URBAN_HS_CONFIG_FILE"),
        log_level=os.environ.get("URBAN_HS_LOG_LEVEL", "INFO"),
    )


@app.on_event("shutdown")
async def _shutdown() -> None:
    await shutdown_core()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# System info
# ---------------------------------------------------------------------------
@app.get("/api/v1/system/info")
async def system_info() -> Dict[str, Any]:
    import platform

    try:
        from urban_hs.core.config import Config

        cfg = Config()
    except Exception:
        cfg = None

    return {
        "version": "3.0.0",
        "arch": platform.machine(),
        "system": platform.system(),
        "release": platform.release(),
        "python": platform.python_version(),
    }


# ---------------------------------------------------------------------------
# Device registry (very thin wrapper over storage for now)
# ---------------------------------------------------------------------------
@app.get("/api/v1/devices")
async def list_devices(limit: int = 100) -> Dict[str, Any]:
    try:
        from urban_hs.core.storage import get_storage

        storage = get_storage()
        rows = await storage.fetchall(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?", (limit,)
        )
        return {"devices": [dict(r) for r in rows]}
    except Exception as exc:
        return {"devices": [], "error": str(exc)}


# ---------------------------------------------------------------------------
# WebSocket: live event bus stream
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active.remove(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        for ws in list(self.active):
            try:
                await ws.send_json(message)
            except Exception:
                self.disconnect(ws)


manager = ConnectionManager()


@app.websocket("/ws/events")
async def ws_events(websocket: WebSocket) -> Any:
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            await websocket.send_json({"type": "ack", "echo": data})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


# ---------------------------------------------------------------------------
# Static frontend mount (to be created in a later phase)
# ---------------------------------------------------------------------------
# from fastapi.staticfiles import StaticFiles
# app.mount("/", StaticFiles(directory="src/urban_hs/ui/web", html=True), name="web")


def run() -> None:
    """Console script entry point."""
    import uvicorn

    uvicorn.run(
        "urban_hs.ui.api.main:app",
        host="0.0.0.0",
        port=int(os.environ.get("URBAN_HS_API_PORT", "8000")),
        reload=bool(os.environ.get("URBAN_HS_API_RELOAD")),
        log_level=os.environ.get("URBAN_HS_LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    run()
