from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from urban_hs.modules.wifi.scanner import NetworkInfo


class WiFiBackend(ABC):
    """Hardware-agnostic WiFi backend interface."""

    @abstractmethod
    async def scan(
        self, channels: list[int] | None = None, duration: int = 30
    ) -> list[NetworkInfo]: ...

    @abstractmethod
    async def set_channel(self, channel: int) -> bool: ...

    @abstractmethod
    async def set_mode(self, mode: str) -> bool: ...

    @abstractmethod
    def name(self) -> str: ...


# ---------------------------------------------------------------------------
# iw-based backend (original Raspberry Pi implementation)
# ---------------------------------------------------------------------------
class _IWBackend(WiFiBackend):
    def __init__(self, interface: str, strategy: str = "passive_only") -> None:
        self.interface = interface
        self.strategy = strategy

    async def scan(self, channels=None, duration=30) -> list[NetworkInfo]:
        from urban_hs.modules.wifi.scanner import ScanStrategy, WiFiScanner

        scanner = WiFiScanner(interface=self.interface, strategy=ScanStrategy(self.strategy))
        return await scanner.scan(channels=channels, duration=duration)

    async def set_channel(self, channel: int) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "iw",
                "dev",
                self.interface,
                "set",
                "channel",
                str(channel),
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def set_mode(self, mode: str) -> bool:
        try:
            cmds = [
                ["ip", "link", "set", self.interface, "down"],
                ["iw", "dev", self.interface, "set", "type", mode],
                ["ip", "link", "set", self.interface, "up"],
            ]
            for cmd in cmds:
                proc = await asyncio.create_subprocess_exec(
                    *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                if proc.returncode != 0:
                    return False
            return True
        except Exception:
            return False

    def name(self) -> str:
        return "iw"


# ---------------------------------------------------------------------------
# scapy-based backend (x86 fallback, no monitor mode required)
# ---------------------------------------------------------------------------
class _ScapyBackend(WiFiBackend):
    def __init__(self, interface: str) -> None:
        self.interface = interface

    async def scan(self, channels=None, duration=30) -> list[NetworkInfo]:
        try:
            from scapy.all import AsyncSniffer  # type: ignore[import-untyped]
        except Exception:
            return []

        found: dict[str, NetworkInfo] = {}

        def _pkt(pkt) -> Any:
            try:
                if pkt.haslayer("Dot11Beacon") or pkt.haslayer("Dot11ProbeResp"):
                    bssid = pkt.addr3 if hasattr(pkt, "addr3") else ""
                    ssid = ""
                    if hasattr(pkt, "payload") and hasattr(pkt.payload, "info"):
                        ssid = pkt.payload.info.decode(errors="replace")
                    rssi = -100
                    if hasattr(pkt, "dBm_AntSignal"):
                        rssi = pkt.dBm_AntSignal
                    if bssid:
                        found.setdefault(
                            bssid,
                            NetworkInfo(
                                bssid=bssid,
                                ssid=ssid,
                                encryption="UNKNOWN",
                                signal_dbm=rssi,
                                channel=0,
                                frequency=0,
                                bandwidth="UNKNOWN",
                            ),
                        )
            except Exception:
                pass

        sniffer = AsyncSniffer(iface=self.interface, prn=_pkt, store=False)
        sniffer.start()
        await asyncio.sleep(duration)
        sniffer.stop()
        return list(found.values())

    async def set_channel(self, channel: int) -> bool:
        return False

    async def set_mode(self, mode: str) -> bool:
        return False

    def name(self) -> str:
        return "scapy"


@dataclass
class InterfaceCapabilities:
    interface: str
    monitor_supported: bool = False
    injection_supported: bool = False
    bands_supported: list[str] = field(default_factory=list)  # ["2.4GHz", "5GHz", "6GHz"]
    driver: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "interface": self.interface,
            "monitor_supported": self.monitor_supported,
            "injection_supported": self.injection_supported,
            "bands_supported": self.bands_supported,
            "driver": self.driver,
        }


async def detect_interface_capabilities(interface: str) -> InterfaceCapabilities:
    """Probe hardware capabilities of ``interface`` via ``iw phy`` (Issue #1.1)."""
    import shutil

    caps = InterfaceCapabilities(interface=interface)
    iw_bin = shutil.which("iw")
    if not iw_bin:
        return caps

    try:
        proc = await asyncio.create_subprocess_exec(
            iw_bin, "phy", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        text = stdout.decode(errors="replace")

        # Parse supported interface modes
        if "monitor" in text.lower():
            caps.monitor_supported = True
        if "AP" in text or "mesh point" in text:
            caps.injection_supported = True

        # Parse bands
        bands = []
        if "2412 MHz" in text or "2.4 GHz" in text or "Frequencies:" in text:
            bands.append("2.4GHz")
        if "5180 MHz" in text or "5 GHz" in text:
            bands.append("5GHz")
        if "5955 MHz" in text or "6 GHz" in text:
            bands.append("6GHz")

        caps.bands_supported = bands or ["2.4GHz"]
    except Exception:
        pass

    return caps


# ---------------------------------------------------------------------------
# Factory
# ---------------------------------------------------------------------------
async def create_wifi_backend(interface: str, strategy: str = "passive_only") -> WiFiBackend:
    """Select the best available backend for ``interface``.

    Preference order:
    1. ``iw`` backend (requires mac80211 + airckack-ng)
    2. ``scapy`` backend (passive, no monitor mode required)
    """
    backend = _IWBackend(interface=interface, strategy=strategy)
    try:
        ok = await backend.set_mode("monitor")
    except Exception:
        ok = False
    return backend if ok else _ScapyBackend(interface=interface)
