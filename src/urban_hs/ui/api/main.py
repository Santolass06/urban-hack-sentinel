"""
Urban Hack Sentinel v3 — FastAPI backend (REST + WebSocket).

Entry point::

    urban-hs-server

The ``run`` helper is registered as a console script in
``pyproject.toml`` (``urban-hs-server``).

.. warning::

    Esta API NUNCA deve ser vinculada a 0.0.0.0 ou exposta fora de
    localhost sem adicionar autenticação real primeiro — o token JWT
    atual não verifica identidade, só gera uma sessão.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from urban_hs import __version__
from urban_hs.core.config import get_config
from urban_hs.core.event_bus import init_event_bus, shutdown_event_bus
from urban_hs.ui.api.rate_limit import limiter

logger = logging.getLogger(__name__)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    await init_event_bus()
    yield
    await shutdown_event_bus()


def _build_app() -> FastAPI:
    root = Path(__file__).resolve().parents[2]  # src/urban_hs
    web_root = root / "ui" / "web"

    application = FastAPI(
        title="Urban Hack Sentinel API",
        description="REST + WebSocket control plane.",
        version=__version__,
        lifespan=_lifespan,
    )
    application.state.limiter = limiter
    application.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

    from urban_hs.core.config import get_config
    cfg = get_config()

    application.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.api.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
        allow_headers=["Authorization", "Content-Type"],
    )

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

    from fastapi import APIRouter

    auth_router = APIRouter(prefix="/api/v1/auth", tags=["auth"])

    @auth_router.post("/token")
    async def create_token() -> dict[str, str]:
        from urban_hs.ui.api.auth import create_access_token
        token = create_access_token(subject="api-user", expires_minutes=cfg.api.jwt_expire_minutes)
        return {"access_token": token, "token_type": "bearer"}

    application.include_router(auth_router)

    @application.get("/healthz", include_in_schema=False)
    async def _healthz_root() -> dict[str, str]:
        return {"status": "ok"}

    if web_root.exists():
        @application.get("/", include_in_schema=False)
        async def _serve_index() -> FileResponse:
            return FileResponse(str(web_root / "index.html"))

        application.mount(
            "/static", StaticFiles(directory=str(web_root)), name="web-static"
        )

    return application


app = _build_app()

from urban_hs.ui.api.middleware import (  # noqa: E402
    IPAllowlistMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)

cfg = get_config()
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(IPAllowlistMiddleware, enabled=cfg.api.enable_ip_allowlist, allowed_ips=cfg.api.allowed_ips)
app.add_middleware(RateLimitMiddleware, requests_per_minute=cfg.api.rate_limit_per_minute)


def run() -> None:
    """Console script entry point for ``urban-hs-server``."""
    import uvicorn

    from urban_hs.core.config import get_config

    cfg = get_config()
    uvicorn.run(app, host=cfg.api.host, port=cfg.api.port)
