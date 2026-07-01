"""
Bettercap BLE module — interacts with a running bettercap instance to
enumerate BLE/GATT devices as a complementary source to bleak.

Expects bettercap running with REST API exposed (default :8081), e.g.:

    bettercap -iface hci0 -eval "ble.enable; api.rest on"

All I/O is performed over the REST API; no direct HCI/bettercap internals.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp

from urban_hs.core.event_bus import Event, EventBus

logger = logging.getLogger(__name__)


@dataclass
class BettercapBLEDevice:
    address: str
    name: Optional[str]
    rssi: Optional[int]
    company: Optional[str]
    raw: Dict[str, Any] = field(default_factory=dict)


class BettercapBLEClient:
    """Minimal bettercap REST client for BLE enumeration."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8081",
        event_bus: Optional[EventBus] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.event_bus = event_bus

    async def enumerate_devices(self, duration: float = 5.0) -> List[BettercapBLEDevice]:
        logger.info("Starting bettercap BLE enumeration", duration=duration)
        devices: List[BettercapBLEDevice] = []
        try:
            modules = await self._get("api/ble/modules")
            if modules.get("modules") != modules.get("modules") == {}:
                logger.warning("BLE modules unavailable in bettercap response")
        except Exception as exc:
            logger.error("BLE modules check failed", error=str(exc))
            return []

        start_time = datetime.utcnow()
        try:
            begin = await self._post("api/ble/on")
            logger.debug("BLE on", begin=begin)
        except Exception as exc:
            logger.error("Failed to enable BLE in bettercap", error=str(exc))

        # Allow time to collect advertisements.
        await asyncio.sleep(duration)

        devs = []
        try:
            devs = await self._get("api/ble/devices")
        except Exception as exc:
            logger.error("Failed to list BLE devices", error=str(exc))

        raw = devs.get("devices", []) if isinstance(devs, dict) else []
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            address = entry.get("address") or entry.get("bdaddr") or ""
            if not address:
                continue
            devices.append(
                BettercapBLEDevice(
                    address=address,
                    name=entry.get("name") or entry.get("local_name"),
                    rssi=entry.get("rssi"),
                    company=entry.get("company"),
                    raw=entry,
                )
            )
        logger.info("bettercap BLE enumeration complete", devices=len(devices))

        if self.event_bus is not None:
            for device in devices:
                try:
                    self.event_bus.publish(
                        "ble.discovered",
                        {
                            "address": device.address,
                            "name": device.name,
                            "rssi": device.rssi,
                            "company": device.company,
                        },
                    )
                except Exception as exc:
                    logger.debug("ble.discovered publish failed", error=str(exc))

        elapsed = (datetime.utcnow() - start_time).total_seconds()
        logger.info("BLE scan elapsed", elapsed=elapsed, devices=len(devices))
        if self.event_bus is not None:
            try:
                self.event_bus.publish(
                    "scan.completed",
                    {
                        "module": "bettercap_ble",
                        "duration": elapsed,
                        "count": len(devices),
                    },
                )
            except Exception as exc:
                logger.debug("scan.completed publish failed", error=str(exc))
        return devices

    async def stop(self) -> None:
        try:
            await self._post("api/ble/off")
        except Exception as exc:
            logger.debug("Failed to disable BLE in bettercap", error=str(exc))

    async def _get(self, path: str) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                resp.raise_for_status()
                return await resp.json()

    async def _post(self, path: str) -> Dict[str, Any]:
        url = f"{self.base_url}/{path.lstrip('/')}"
        async with aiohttp.ClientSession() as session:
            async with session.post(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                resp.raise_for_status()
                return await resp.json()