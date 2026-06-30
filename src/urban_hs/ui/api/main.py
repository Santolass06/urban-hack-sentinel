"""
Urban Hack Sentinel v3 — FastAPI backend (REST + WebSocket).

Entry point::

    uvicorn urban_hs.ui.api.main:run --host 0.0.0.0 --port 8000

The ``run`` helper is registered as a console script in
``pyproject.toml`` (``urban-hs-server``).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from urban_hs import __version__
from urban_hs.core.config import get_config
from urban_hs.core.event_bus import init_event_bus, shutdown_event_bus

logger = logging.getLogger(__name__)


def _build_app() -> FastAPI:
    root = Path(__file__).resolve().parents[2]  # src/urban_hs
    web_root = root / "ui" / "web"

    application = FastAPI(
        title="Urban Hack Sentinel API",
        description="REST + WebSocket control plane.",
        version=__version__,
    )

    @application.on_event("startup")
    async def _on_startup() -> None:
        await init_event_bus()

    @application.on_event("shutdown")
    async def _on_shutdown() -> None:
        await shutdown_event_bus()

    from urban_hs.ui.api.routers.system import router as system_router
    application.include_router(system_router, prefix="/api/v1")

    from urban_hs.ui.api.routers.wifi import router as wifi_router
    application.include_router(wifi_router, prefix="/api/v1/wifi")

    from urban_hs.ui.api.routers.ble import router as ble_router
    application.include_router(ble_router, prefix="/api/v1/ble")

    from urban_hs.ui.api.routers.network import router as network_router
    application.include_router(network_router, prefix="/api/v1/network")

    from urban_hs.ui.api.routers.events import router as events_router
    application.include_router(events_router)

    from urban_hs.ui.api.routers.attacks import router as attacks_router
    application.include_router(attacks_router, prefix="/api/v1")

    if web_root.exists():
        @application.get("/", include_in_schema=False)
        async def _serve_index() -> FileResponse:
            return FileResponse(str(web_root / "index.html"))

        application.mount(
            "/static", StaticFiles(directory=str(web_root)), name="web-static"
        )

    return application


app = _build_app()

# Sprint 8A hardening stack.
# Middlewares run in reverse registration order, so the security headers
# wrapper should be the outermost layer.
from urban_hs.ui.api.middleware import (  # noqa: E402
    IPAllowlistMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)

cfg = get_config()
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(IPAllowlistMiddleware, enabled=cfg.api.enable_ip_allowlist, allowed_ips=cfg.api.allowed_ips)
app.add_middleware(RateLimitMiddleware, requests_per_minute=cfg.api.rate_limit_per_minute)
