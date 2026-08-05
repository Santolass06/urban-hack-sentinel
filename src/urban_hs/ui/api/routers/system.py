"""
System control-plane endpoints.
"""

from __future__ import annotations

from typing import Any

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


@router.get("/status", dependencies=[require_auth()])
async def system_status() -> dict[str, Any]:
    """Get system runtime metrics and status (F2.2)."""
    import os
    import time
    try:
        import psutil
        cpu_percent = psutil.cpu_percent()
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
    except Exception:
        cpu_percent = 0.0
        mem_percent = 0.0

    return {
        "status": "healthy",
        "uptime_sec": time.monotonic(),
        "cpu_percent": cpu_percent,
        "memory_percent": mem_percent,
        "pid": os.getpid(),
    }


@router.get("/cracked", dependencies=[require_auth()])
async def list_cracked_hashes() -> dict[str, Any]:
    """Get list of cracked hashes from potfile / storage (F2.6)."""
    from pathlib import Path
    from urban_hs.core.config import get_config

    cracked_dir = Path(get_config().storage.resolve_wifi_attacks_dir()) / "cracked"
    cracked_items = []
    if cracked_dir.exists():
        for pot_file in cracked_dir.glob("*.potfile"):
            try:
                lines = pot_file.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    if ":" in line:
                        parts = line.split(":", 2)
                        cracked_items.append({"hash": parts[0], "password": parts[1] if len(parts) > 1 else ""})
            except Exception:
                pass

    return {"cracked": cracked_items, "total": len(cracked_items)}
