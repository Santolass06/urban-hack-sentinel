"""
Hashtopolis REST API Offloading Client (Issue #4.1).

Allows automated uploading of captured WPA/WPA2/PMKID hash files (.22000 format)
to a remote Hashtopolis server fleet for distributed hashcat cracking.
"""

from __future__ import annotations

import asyncio
import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class HashtopolisTask:
    task_id: int
    name: str
    status: str
    keyspace_progress: float = 0.0


class HashtopolisClient:
    """Async Hashtopolis REST API Client for hash offloading."""

    def __init__(self, server_url: str | None = None, api_token: str | None = None):
        if server_url is None or api_token is None:
            from urban_hs.core.config import get_config
            cfg = get_config()
            server_url = getattr(cfg, "hashtopolis_url", "") or "http://localhost:8080/api/v2"
            api_token = getattr(cfg, "hashtopolis_token", "") or ""
        self.server_url = server_url.rstrip("/")
        self.api_token = api_token

    async def upload_hash_file(self, hash_file: Path, task_name: str = "urban-hs-auto") -> HashtopolisTask | None:
        """Upload a .22000 hash file to Hashtopolis for remote cracking."""
        if not hash_file.exists():
            logger.warning("Hash file does not exist", path=str(hash_file))
            return None

        if not self.api_token:
            logger.info("Hashtopolis API token not configured, skipping remote upload", path=str(hash_file))
            return None

        try:
            content = hash_file.read_text(encoding="utf-8")
            payload = {
                "section": "hashlist",
                "request": "createHashlist",
                "name": f"{task_name}_{hash_file.stem}",
                "format": 0,  # Single hash / hashlist
                "hashtype": 22000,  # WPA-PBKDF2-PMKID+EAPOL
                "data": content,
                "accessGroup": 1,
                "token": self.api_token,
            }

            loop = asyncio.get_running_loop()
            req = urllib.request.Request(
                f"{self.server_url}/user.php",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            res_bytes = await loop.run_in_executor(
                None, lambda: urllib.request.urlopen(req, timeout=15).read()
            )
            res_data = json.loads(res_bytes.decode())

            if res_data.get("response") == "OK":
                hashlist_id = res_data.get("hashlistId", 0)
                logger.info("Successfully uploaded hash file to Hashtopolis", hashlist_id=hashlist_id)
                return HashtopolisTask(task_id=hashlist_id, name=task_name, status="QUEUED")
        except Exception as exc:
            logger.warning("Failed to upload hash file to Hashtopolis", path=str(hash_file), error=str(exc))

        return None
