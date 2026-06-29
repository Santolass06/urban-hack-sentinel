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
        self,
        channels: Optional[List[int]] = None,
        duration: int = 30,
    ) -> List[NetworkInfo]:
        ...

    @abstractmethod
    async def set_channel(self, channel: int) -> bool:
        ...

    @abstractmethod
    async def set_mode(self, mode: str) -> bool:
        ...

    @abstractmethod
    def name(self) -> str:
        ...


# ---------------------------------------------------------------------------
# iw-based backend (original Raspberry Pi implementation)
# ---------------------------------------------------------------------------
class _IWBackend(WiFiBackend):
    def __init__(self, interface: str, strategy: str = "passive_only") -> None:
        self.interface = interface
        self.strategy = strategy

    async def scan(self, channels=None, duration=30) -> List[NetworkInfo]:
        from urban_hs.modules.wifi.scanner import WiFiScanner, ScanStrategy

        scanner = WiFiScanner(
            interface=self.interface,
            strategy=ScanStrategy(self.strategy),
        )
        return await scanner.scan(channels=channels, duration=duration)

    async def set_channel(self, channel: int) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                "iw", "dev", self.interface, "set", "channel", str(channel),
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
                    *cmd,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
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

    async def scan(self, channels=None, duration=30) -> List[NetworkInfo]:
        try:
            from scapy.all import AsyncSniffer  # type: ignore[import-untyped]
        except Exception:
            return []

        found: Dict[str, NetworkInfo] = {}

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
                        found.setdefault(bssid, NetworkInfo(
                            bssid=bssid,
                            ssid=ssid,
                            encryption="UNKNOWN",
                            signal_dbm=rssi,
                            channel=0,
                            frequency=0,
                            bandwidth="UNKNOWN",
                        ))
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
