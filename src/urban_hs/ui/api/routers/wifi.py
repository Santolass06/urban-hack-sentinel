"""
WiFi scan + attack endpoints.

These endpoints live behind the main API router:
    app.include_router(wifi.router, prefix=\"/api/v1/wifi\", tags=[\"wifi\"])
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from typing import Any

from fastapi import APIRouter, Request

from urban_hs.ui.api.auth import require_auth
from urban_hs.ui.api.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[require_auth()])


@router.get("/interfaces")
async def list_wifi_interfaces() -> dict[str, Any]:
    import os
    import shutil

    ifaces: list[str] = []
    iw = shutil.which("iw")
    if iw:
        try:
            proc = await asyncio.create_subprocess_exec(
                iw, "dev", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await proc.communicate()
            text = stdout.decode(errors="replace")
            for line in text.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    ifaces.append(line.split()[1])
        except Exception as exc:
            logger.warning("iw dev failed: %s", exc)

    if not ifaces and os.path.exists("/sys/class/net"):
        try:
            for entry in os.listdir("/sys/class/net"):
                if entry.startswith(("wlan", "wlo", "wlp", "wlx")) or os.path.exists(
                    f"/sys/class/net/{entry}/wireless"
                ):
                    if entry not in ifaces:
                        ifaces.append(entry)
        except Exception as exc:
            logger.warning("sysfs net scan failed: %s", exc)

    return {"interfaces": ifaces}


@router.post("/scan")
@limiter.limit("10/minute")
async def start_wifi_scan(
    request: Request, interface: str = "wlan1", strategy: str = "passive_only"
) -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    payload: dict[str, Any] = {
        "job_id": job_id,
        "interface": interface,
        "strategy": strategy,
        "status": "queued",
    }

    async def _run() -> None:
        try:
            from urban_hs.core import get_event_bus
            from urban_hs.core.event_bus import Event
            from urban_hs.modules.wifi import ScanStrategy, WiFiScanner

            bus = get_event_bus()
            await bus.publish(
                Event(
                    type="wifi.scan.started",
                    payload={"job_id": job_id, "interface": interface, "strategy": strategy},
                    source="api",
                )
            )

            scanner = WiFiScanner(interface=interface, strategy=ScanStrategy(strategy))
            networks: list[Any] = []
            simulated = False
            try:
                nets = await scanner.scan(duration=30)
                networks = [n.to_dict() for n in nets]
            except Exception as exc:
                logger.warning("WiFi scan failed, no fallback: %s", exc)
                await bus.publish(
                    Event(
                        type="wifi.scan.error",
                        payload={"job_id": job_id, "error": str(exc)},
                        source="api",
                    )
                )
                payload.update({"status": "error", "error": str(exc)})
                return

            await bus.publish(
                Event(
                    type="wifi.scan.completed",
                    payload={
                        "job_id": job_id,
                        "count": len(networks),
                        "networks": networks,
                        "simulated": simulated,
                    },
                    source="api",
                )
            )
            payload.update(
                {
                    "status": "completed",
                    "count": len(networks),
                    "networks": networks,
                    "simulated": simulated,
                }
            )
        except Exception as exc:
            payload.update({"status": "error", "error": str(exc)})

    asyncio.create_task(_run())
    return payload


@router.get("/jobs/{job_id}")
async def get_wifi_scan_job(job_id: str) -> dict[str, Any]:
    return {"job_id": job_id, "status": "unknown"}


@router.get("/capabilities/{interface}")
async def get_interface_capabilities(interface: str) -> dict[str, Any]:
    """Return auto-detected capabilities for a given Wi-Fi interface (Issue #1.1)."""
    from urban_hs.hal.wifi import detect_interface_capabilities

    caps = await detect_interface_capabilities(interface)
    return caps.to_dict()


@router.get("/map-data")
async def get_map_data() -> dict[str, Any]:
    """Return GPS-localized Wi-Fi and BLE networks for Leaflet map rendering (Issue #1.2)."""
    from urban_hs.core.storage import get_storage

    try:
        storage = get_storage()
        # Query devices with GPS metadata or coordinates
        rows = await storage.fetchall(
            "SELECT id, mac, type, meta FROM devices WHERE meta LIKE '%lat%' OR meta LIKE '%gps%'"
        )
        points = []
        for row in rows:
            meta = json.loads(row.get("meta", "{}"))
            if "lat" in meta and "lon" in meta:
                points.append(
                    {
                        "id": row.get("id"),
                        "mac": row.get("mac"),
                        "type": row.get("type"),
                        "lat": meta.get("lat"),
                        "lon": meta.get("lon"),
                        "ssid": meta.get("ssid", "Hidden"),
                        "signal_dbm": meta.get("signal_dbm", -70),
                        "encryption": meta.get("encryption", "WPA2"),
                    }
                )
        return {"points": points, "total": len(points)}
    except Exception as exc:
        return {"points": [], "total": 0, "error": str(exc)}
