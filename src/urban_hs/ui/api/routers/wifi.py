"""
WiFi scan + attack endpoints.

These endpoints live behind the main API router:
    app.include_router(wifi.router, prefix=\"/api/v1/wifi\", tags=[\"wifi\"])
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict

from fastapi import APIRouter

from urban_hs.ui.api.auth import require_auth

router = APIRouter(dependencies=[require_auth()])


@router.get("/interfaces")
async def list_wifi_interfaces() -> Dict[str, Any]:
    import shutil

    iw = shutil.which("iw")
    if not iw:
        return {"interfaces": [], "error": "iw tool not found"}

    try:
        proc = await asyncio.create_subprocess_exec(
            iw, "dev",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode(errors="replace")
        ifaces: list[str] = []
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("Interface "):
                ifaces.append(line.split()[1])
        return {"interfaces": ifaces}
    except Exception as exc:
        return {"interfaces": [], "error": str(exc)}


@router.post("/scan")
async def start_wifi_scan(interface: str = "wlan1", strategy: str = "passive_only") -> Dict[str, Any]:
    job_id = str(uuid.uuid4())
    payload: Dict[str, Any] = {
        "job_id": job_id,
        "interface": interface,
        "strategy": strategy,
        "status": "queued",
    }

    async def _run() -> None:
        try:
            from urban_hs.core import get_event_bus
            from urban_hs.core.event_bus import Event
            from urban_hs.modules.wifi import WiFiScanner, ScanStrategy

            bus = get_event_bus()
            await bus.publish(Event(
                type="wifi.scan.started",
                payload={"job_id": job_id, "interface": interface, "strategy": strategy},
                source="api",
            ))

            scanner = WiFiScanner(interface=interface, strategy=ScanStrategy(strategy))
            networks: list[Any] = []
            try:
                nets = await scanner.scan(duration=30)
                networks = [n.to_dict() for n in nets]
            except Exception as exc:
                await bus.publish(Event(
                    type="wifi.scan.error",
                    payload={"job_id": job_id, "error": str(exc)},
                    source="api",
                ))
                payload.update({"status": "error", "error": str(exc)})
                return

            await bus.publish(Event(
                type="wifi.scan.completed",
                payload={"job_id": job_id, "count": len(networks), "networks": networks},
                source="api",
            ))
            payload.update({"status": "completed", "count": len(networks), "networks": networks})
        except Exception as exc:
            payload.update({"status": "error", "error": str(exc)})

    asyncio.create_task(_run())
    return payload


@router.get("/jobs/{job_id}")
async def get_wifi_scan_job(job_id: str) -> Dict[str, Any]:
    return {"job_id": job_id, "status": "unknown"}
