"""
Network scan endpoints.

Mount with prefix \"/api/v1/network\".
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Request

from urban_hs.ui.api.auth import require_auth
from urban_hs.ui.api.rate_limit import limiter

router = APIRouter(dependencies=[require_auth()])


@router.post("/scan")
@limiter.limit("10/minute")
async def start_network_scan(
    request: Request,
    target: str = "192.168.1.0/24",
    scan_type: str = "host_discovery",
    timeout: int = 300,
) -> Dict[str, Any]:
    job_id = str(uuid.uuid4())
    payload: Dict[str, Any] = {
        "job_id": job_id,
        "target": target,
        "scan_type": scan_type,
        "timeout": timeout,
        "status": "queued",
    }

    from urban_hs.core import get_event_bus
    from urban_hs.core.event_bus import Event
    from urban_hs.modules.network import NetworkModule, ScanType

    bus = get_event_bus()
    module = NetworkModule()

    def _build_scan_type(value: str):
        try:
            return ScanType(value)
        except Exception:
            return ScanType.HOST_DISCOVERY

    async def _run() -> None:
        try:
            await bus.publish(Event(
                type="network.scan.started",
                payload={"job_id": job_id, "target": target, "scan_type": scan_type},
                source="api",
            ))
            hosts = await module.nmap.scan(
                [target],
                scan_type=_build_scan_type(scan_type),
                timeout=timeout,
            )
            result = [vars(h) for h in hosts]
            await bus.publish(Event(
                type="network.scan.completed",
                payload={"job_id": job_id, "count": len(result), "hosts": result},
                source="api",
            ))
            payload.update({"status": "completed", "count": len(result), "hosts": result})
        except Exception as exc:
            await bus.publish(Event(
                type="network.scan.error",
                payload={"job_id": job_id, "error": str(exc)},
                source="api",
            ))
            payload.update({"status": "error", "error": str(exc)})

    asyncio.create_task(_run())
    return payload


@router.get("/jobs/{job_id}")
async def get_network_scan_job(job_id: str) -> Dict[str, Any]:
    return {"job_id": job_id, "status": "unknown"}
