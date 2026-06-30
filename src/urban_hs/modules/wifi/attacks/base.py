"""
WiFi Attack base classes and shared types.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)


class AttackStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


@dataclass
class AttackResult:
    """Result of an attack execution."""
    attack_type: str
    target_bssid: str
    target_essid: Optional[str]
    status: AttackStatus
    started_at: datetime
    finished_at: Optional[datetime] = None
    output_files: List[str] = field(default_factory=list)
    handshake_path: Optional[str] = None
    pmkid_path: Optional[str] = None
    wps_pin: Optional[str] = None
    wps_psk: Optional[str] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> Optional[float]:
        if self.finished_at:
            return (self.finished_at - self.started_at).total_seconds()
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type,
            "target_bssid": self.target_bssid,
            "target_essid": self.target_essid,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": self.duration_seconds,
            "output_files": self.output_files,
            "handshake_path": self.handshake_path,
            "pmkid_path": self.pmkid_path,
            "wps_pin": self.wps_pin,
            "wps_psk": self.wps_psk,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class BaseAttack(ABC):
    """Abstract base class for WiFi attacks."""

    def __init__(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        attack_timeout: int = 60,
    ):
        self.interface = interface
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = get_config().storage.resolve_wifi_attacks_dir()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.attack_timeout = attack_timeout
        self._running = False
        self._cancelled = False

    @abstractmethod
    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        """Execute the attack against a target."""
        pass

    def _log(self, message: str, **kwargs) -> None:
        logger.info(message, **kwargs)

    def _notify_callback(self, callback: Optional[Callable[[str], None]], message: str) -> None:
        if callback:
            try:
                callback(message)
            except Exception:
                pass

    async def _start_airodump(
        self,
        bssid: str,
        channel: int,
        output_prefix: str,
    ) -> asyncio.subprocess.Process:
        """Start airodump-ng capture."""
        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", output_prefix,
            "--output-format", "pcap",
            self.interface,
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc

    async def _run_hcxdumptool(
        self,
        bssid: str,
        channel: int,
        output_file: Path,
        timeout: int,
    ) -> asyncio.subprocess.Process:
        """Run hcxdumptool for PMKID capture."""
        cmd = [
            "hcxdumptool",
            "-i", self.interface,
            "--filterlist_ap", bssid,
            "--filtermode", "2",
            "-c", str(channel),
            "-o", str(output_file),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        return proc
