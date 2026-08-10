"""
WiGLE.net API Client — Query global wireless geolocalisation database.

Academic / API Reference: https://wigle.net/api/v2
Allows querying BSSID location and SSIDs to enrich local wardriving intelligence.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class WigleLocation:
    bssid: str
    ssid: str | None = None
    lat: float | None = None
    lon: float | None = None
    country: str | None = None
    city: str | None = None


class WigleClient:
    """Async WiGLE.net REST API v2 client (Issue #2.2)."""

    def __init__(self, api_name: str | None = None, api_key: str | None = None):
        if api_name is None or api_key is None:
            from urban_hs.core.config import get_config

            cfg = get_config()
            api_name = getattr(cfg, "wigle_api_name", "") or None
            api_key = getattr(cfg, "wigle_api_key", "") or None
        self.api_name = api_name
        self.api_key = api_key

    async def search_bssid(self, bssid: str) -> WigleLocation | None:
        """Query WiGLE API for coordinates matching BSSID."""
        if not self.api_name or not self.api_key:
            logger.info("WiGLE API credentials not set, skipping remote query", bssid=bssid)
            return None

        import base64
        import json
        import urllib.parse
        import urllib.request

        url = f"https://api.wigle.net/api/v2/network/search?netid={urllib.parse.quote(bssid)}"
        auth_header = base64.b64encode(f"{self.api_name}:{self.api_key}".encode()).decode()

        req = urllib.request.Request(
            url, headers={"Authorization": f"Basic {auth_header}", "Accept": "application/json"}
        )

        try:
            loop = asyncio.get_running_loop()
            res_bytes = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=10).read()
            )
            data = json.loads(res_bytes.decode())
            results = data.get("results", [])
            if results:
                item = results[0]
                return WigleLocation(
                    bssid=bssid,
                    ssid=item.get("ssid"),
                    lat=item.get("trilat"),
                    lon=item.get("trilong"),
                    country=item.get("country"),
                    city=item.get("city"),
                )
        except Exception as exc:
            logger.warning("WiGLE API lookup failed", bssid=bssid, error=str(exc))

        return None
