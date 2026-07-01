"""
BLE endpoints.

Mount with prefix \"/api/v1/ble\".
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Dict

from fastapi import APIRouter, Request

from urban_hs.ui.api.auth import require_auth
from urban_hs.ui.api.rate_limit import limiter

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[require_auth()])


@router.post("/scan")
@limiter.limit("10/minute")
async def start_ble_scan(request: Request, duration: int = 10) -> Dict[str, Any]:
    job_id = str(uuid.uuid4())
    payload: Dict[str, Any] = {
        "job_id": job_id,
        "duration": duration,
        "status": "queued",
    }

    async def _run() -> None:
        try:
            from urban_hs.core import get_event_bus
            from urban_hs.core.event_bus import Event
            from urban_hs.modules.ble import FastPairScanner

            bus = get_event_bus()
            await bus.publish(Event(
                type="ble.scan.started",
                payload={"job_id": job_id, "duration": duration},
                source="api",
            ))

            scanner = FastPairScanner()
            simulated = False
            try:
                await scanner.start()
                await asyncio.sleep(duration)
            except Exception as exc:
                logger.warning("BLE scan failed, no fallback: %s", exc)
                await bus.publish(Event(
                    type="ble.scan.error",
                    payload={"job_id": job_id, "error": str(exc)},
                    source="api",
                ))
                payload.update({"status": "error", "error": str(exc)})
                return
            finally:
                await scanner.stop()

            devices = scanner.get_devices()
            serialised = [
                d.to_dict() if hasattr(d, "to_dict") else vars(d) for d in devices
            ]

            await bus.publish(Event(
                type="ble.scan.completed",
                payload={
                    "job_id": job_id,
                    "count": len(serialised),
                    "devices": serialised,
                    "simulated": simulated,
                },
                source="api",
            ))
            payload.update({
                "status": "completed",
                "count": len(serialised),
                "devices": serialised,
                "simulated": simulated,
            })
        except Exception as exc:
            payload.update({"status": "error", "error": str(exc)})

    asyncio.create_task(_run())
    return payload


@router.get("/jobs/{job_id}")
async def get_ble_scan_job(job_id: str) -> Dict[str, Any]:
    return {"job_id": job_id, "status": "unknown"}
