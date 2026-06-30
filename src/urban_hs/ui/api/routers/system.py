"""
System control-plane endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter

from urban_hs.ui.api.auth import require_auth

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/info", dependencies=[require_auth()])
async def system_info() -> dict[str, str]:
    try:
        import platform
        from urban_hs import __version__
        return {
            "version": __version__,
            "platform": platform.system(),
            "machine": platform.machine(),
            "release": platform.release(),
        }
    except Exception as exc:
        return {"error": str(exc)}
