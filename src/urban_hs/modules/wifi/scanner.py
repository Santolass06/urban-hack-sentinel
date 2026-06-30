"""
WiFi Scanner - Passive and active WiFi network discovery.

Supports multiple scan strategies:
- passive_only: airodump-ng channel hopping (no probe requests)
- mode_switch: temporary switch to managed mode for iw scan
- direct: iw scan in current mode (if supported)

Outputs structured NetworkInfo objects with encryption, signal, vendor, etc.
"""

import asyncio
import json
import os
import re
import structlog
import subprocess
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Set

logger = structlog.get_logger(__name__)


class ScanStrategy(Enum):
    """Available scan strategies."""
    PASSIVE_ONLY = "passive_only"
    MODE_SWITCH = "mode_switch"
    DIRECT = "direct"


@dataclass
class NetworkInfo:
    """Information about a discovered WiFi network."""
    bssid: str
    ssid: Optional[str] = None
    encryption: str = "UNKNOWN"  # OPEN, WEP, WPA, WPA2, WPA3, OWE, WPS
    signal_dbm: int = -100
    channel: int = 0
    frequency: int = 0
    bandwidth: str = "UNKNOWN"  # HT20, HT40, VHT80, HE160, EHT320
    wps_enabled: bool = False
    wps_locked: bool = False
    pmf: str = "UNKNOWN"  # disabled, optional, required
    vendor: Optional[str] = None
    last_seen: int = field(default_factory=lambda: int(datetime.utcnow().timestamp() * 1000))
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    gps_alt: Optional[float] = None
    gps_accuracy: Optional[float] = None
    meta: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_vulnerable_wps(self) -> bool:
        """Check if network has WPS enabled and not locked."""
        return self.wps_enabled and not self.wps_locked

    @property
    def is_wpa3(self) -> bool:
        return "WPA3" in self.encryption

    def to_dict(self) -> Dict[str, Any]:
        return {
            "bssid": self.bssid,
            "ssid": self.ssid,
            "encryption": self.encryption,
            "signal_dbm": self.signal_dbm,
            "channel": self.channel,
            "frequency": self.frequency,
            "bandwidth": self.bandwidth,
            "wps_enabled": self.wps_enabled,
            "wps_locked": self.wps_locked,
            "pmf": self.pmf,
            "vendor": self.vendor,
            "last_seen": self.last_seen,
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "gps_alt": self.gps_alt,
            "gps_accuracy": self.gps_accuracy,
            "meta": self.meta,
        }


class ScanBackend(ABC):
    """Abstract base for scan implementations."""

    @abstractmethod
    async def scan(self, interface: str, channels: Optional[List[int]] = None, duration: int = 30) -> List[NetworkInfo]:
        """Perform scan and return discovered networks."""
        pass


class IWScanBackend(ScanBackend):
    """Active scan using `iw` command (requires managed mode)."""

    def __init__(self, timeout: int = 15):
        self.timeout = timeout

    async def scan(self, interface: str, channels: Optional[List[int]] = None, duration: int = 30) -> List[NetworkInfo]:
        cmd = ["iw", "dev", interface, "scan", "-f", "json"]
        if channels:
            freq_list = " ".join(str(self._channel_to_freq(c)) for c in channels)
            cmd.extend(["freq", freq_list])

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=self.timeout)

            if process.returncode != 0:
                logger.warning("iw scan failed", stderr=stderr.decode())
                return []

            return self._parse_iw_json(stdout.decode(), interface)
        except asyncio.TimeoutError:
            logger.warning("iw scan timeout")
            return []
        except Exception as e:
            logger.error("iw scan error", error=str(e))
            return []

    def _channel_to_freq(self, channel: int) -> int:
        if 1 <= channel <= 14:
            return 2407 + channel * 5
        elif 36 <= channel <= 165:
            return 5000 + channel * 5
        elif 1 <= channel <= 233:  # 6GHz
            return 5950 + channel * 5
        return 2412

    def _parse_iw_json(self, json_str: str, interface: str) -> List[NetworkInfo]:
        networks = []
        try:
            data = json.loads(json_str)
            for entry in data:
                bssid = entry.get("bssid", "").lower()
                if not bssid:
                    continue

                ssid = entry.get("ssid")
                signal = entry.get("signal", -100)
                freq = entry.get("freq", 0)
                flags = entry.get("flags", [])

                # Determine encryption
                encryption = self._parse_encryption(flags)
                
                # WPS detection
                wps_enabled = "wps" in [f.lower() for f in flags] or "wps" in str(entry).lower()
                
                # PMF detection
                pmf = self._parse_pmf(flags)

                # Channel from frequency
                channel = self._freq_to_channel(freq)

                # Bandwidth
                bandwidth = self._parse_bandwidth(entry)

                # Vendor from OUI
                vendor = self._get_vendor(bssid)

                network = NetworkInfo(
                    bssid=bssid,
                    ssid=ssid,
                    encryption=encryption,
                    signal_dbm=signal,
                    channel=channel,
                    frequency=freq,
                    bandwidth=bandwidth,
                    wps_enabled=wps_enabled,
                    pmf=pmf,
                    vendor=vendor,
                )
                networks.append(network)

        except json.JSONDecodeError as e:
            logger.error("Failed to parse iw JSON", error=str(e))

        return networks

    def _parse_encryption(self, flags: List[str]) -> str:
        flags_lower = [f.lower() for f in flags]
        if "privacy" not in flags_lower:
            return "OPEN"
        if any("wpa3" in f or "sae" in f for f in flags_lower):
            return "WPA3"
        if any("wpa2" in f for f in flags_lower):
            return "WPA2"
        if any("wpa" in f for f in flags_lower):
            return "WPA"
        if any("wep" in f for f in flags_lower):
            return "WEP"
        return "WPA"

    def _parse_pmf(self, flags: List[str]) -> str:
        flags_lower = [f.lower() for f in flags]
        if "mfpc" in flags_lower and "mfpr" in flags_lower:
            return "required"
        elif "mfpc" in flags_lower:
            return "optional"
        return "disabled"

    def _parse_bandwidth(self, entry: Dict) -> str:
        # HT/VHT/HE/EHT capabilities would be in iw output
        if "vht_caps" in entry:
            return "VHT80"
        elif "he_caps" in entry:
            return "HE160"
        elif "eht_caps" in entry:
            return "EHT320"
        elif "ht_caps" in entry:
            return "HT40"
        return "HT20"

    def _freq_to_channel(self, freq: int) -> int:
        if 2412 <= freq <= 2484:
            return (freq - 2407) // 5
        elif 5180 <= freq <= 5825:
            return (freq - 5000) // 5
        elif 5955 <= freq <= 7115:
            return (freq - 5950) // 5
        return 0

    def _get_vendor(self, bssid: str) -> Optional[str]:
        """Lookup vendor from OUI."""
        try:
            oui = bssid[:8].upper().replace(":", "-")
            # Could load from local OUI database
            return None
        except Exception:
            return None


class AirodumpScanBackend(ScanBackend):
    """Passive scan using airodump-ng with channel hopping."""

    def __init__(self, output_dir: Optional[str] = None):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = get_config().storage.resolve_wifi_scans_dir()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def scan(self, interface: str, channels: Optional[List[int]] = None, duration: int = 30) -> List[NetworkInfo]:
        csv_prefix = self.output_dir / f"scan_{uuid.uuid4().hex[:8]}"
        
        cmd = [
            "airodump-ng",
            "--write", str(csv_prefix),
            "--output-format", "csv",
            "--write-interval", "1",
            "--manufacturer",
            "--uptime",
        ]
        
        if channels:
            cmd.extend(["--channel", ",".join(str(c) for c in channels)])

        cmd.append(interface)

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )

            await asyncio.sleep(duration)
            process.terminate()
            await process.wait()

            csv_file = f"{csv_prefix}-01.csv"
            if os.path.exists(csv_file):
                return self._parse_airodump_csv(csv_file)

        except Exception as e:
            logger.error("airodump scan error", error=str(e))

        return []

    def _parse_airodump_csv(self, csv_file: str) -> List[NetworkInfo]:
        networks = []
        try:
            with open(csv_file, 'r') as f:
                lines = f.readlines()

            # Find the AP section (after the header lines)
            in_ap_section = False
            for line in lines:
                line = line.strip()
                if line.startswith("BSSID"):
                    in_ap_section = True
                    continue
                if line.startswith("Station MAC"):
                    break
                if in_ap_section and line:
                    parts = [p.strip() for p in line.split(',')]
                    if len(parts) >= 14:
                        network = self._parse_ap_line(parts)
                        if network:
                            networks.append(network)

        except Exception as e:
            logger.error("Failed to parse airodump CSV", error=str(e))

        return networks

    def _parse_ap_line(self, parts: List[str]) -> Optional[NetworkInfo]:
        try:
            bssid = parts[0].lower()
            if not bssid or bssid == "00:00:00:00:00:00":
                return None

            # parts: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
            channel = int(parts[3]) if parts[3].isdigit() else 0
            privacy = parts[5]
            cipher = parts[6]
            auth = parts[7]
            power = int(parts[8]) if parts[8].lstrip('-').isdigit() else -100
            essid = parts[13] if len(parts) > 13 else None

            encryption = self._parse_privacy(privacy, auth)
            wps_enabled = "wps" in auth.lower()

            return NetworkInfo(
                bssid=parts[0].lower(),
                ssid=essid if essid and essid != "<length: 0>" else None,
                encryption=encryption,
                signal_dbm=power,
                channel=channel,
                wps_enabled=wps_enabled,
                vendor=self._get_vendor(parts[0]),
            )
        except Exception:
            return None

    def _parse_privacy(self, privacy: str, auth: str) -> str:
        privacy_lower = privacy.lower()
        auth_lower = auth.lower()
        if "wpa3" in privacy_lower or "sae" in auth_lower:
            return "WPA3"
        elif "wpa2" in privacy_lower:
            return "WPA2"
        elif "wpa" in privacy_lower:
            return "WPA"
        elif "wep" in privacy_lower:
            return "WEP"
        elif "opn" in privacy_lower:
            return "OPEN"
        return "UNKNOWN"

    def _get_vendor(self, bssid: str) -> Optional[str]:
        # Would load from OUI database
        return None


class ScanManager:
    """
    High-level scan manager that coordinates multiple backends
    and handles mode switching for interfaces that need it.
    """

    def __init__(
        self,
        interface: str,
        strategy: ScanStrategy = ScanStrategy.PASSIVE_ONLY,
        output_dir: Optional[str] = None,
    ):
        self.interface = interface
        self.strategy = strategy
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = get_config().storage.resolve_wifi_scans_dir()
        self.output_dir = output_dir
        
        self.backends = {
            ScanStrategy.DIRECT: IWScanBackend(),
            ScanStrategy.MODE_SWITCH: IWScanBackend(),
            ScanStrategy.PASSIVE_ONLY: AirodumpScanBackend(output_dir=output_dir),
        }
        
        # Known networks cache
        self._known_networks: Dict[str, NetworkInfo] = {}

    async def scan(self, channels: Optional[List[int]] = None, duration: int = 30) -> List[NetworkInfo]:
        """Perform scan based on configured strategy."""
        backend = self.backends.get(self.strategy)
        if not backend:
            logger.error("Unknown scan strategy", strategy=self.strategy)
            return []

        # Handle mode switch for strategies that need it
        await self._ensure_mode()

        if self.strategy == ScanStrategy.MODE_SWITCH:
            # Switch to managed, scan, switch back
            await self._set_mode("managed")
            try:
                networks = await backend.scan(self.interface, duration=duration)
            finally:
                await self._set_mode("monitor")
        else:
            networks = await backend.scan(self.interface, duration=duration)

        # Update cache
        for net in networks:
            key = net.bssid.lower()
            if key in self._known_networks:
                # Merge/update
                existing = self._known_networks[key]
                existing.last_seen = net.last_seen
                existing.signal_dbm = max(existing.signal_dbm, net.signal_dbm)
                if net.ssid:
                    existing.ssid = net.ssid
            else:
                self._known_networks[key] = net

        return list(self._known_networks.values())

    async def _ensure_mode(self) -> None:
        """Check and set interface to monitor mode if needed."""
        current = await self._get_current_mode()
        if current != "monitor":
            await self._set_mode("monitor")

    async def _get_current_mode(self) -> str:
        try:
            proc = await asyncio.create_subprocess_exec(
                "iw", "dev", self.interface, "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await proc.communicate()
            for line in stdout.decode().split('\n'):
                if line.strip().startswith("type"):
                    return line.split()[1].strip()
        except Exception:
            pass
        return "unknown"

    async def _set_mode(self, mode: str) -> None:
        if mode == "monitor":
            await self._run_cmd(["ip", "link", "set", self.interface, "down"])
            await self._run_cmd(["iw", "dev", self.interface, "set", "type", "monitor"])
            await self._run_cmd(["ip", "link", "set", self.interface, "up"])
        elif mode == "managed":
            await self._run_cmd(["ip", "link", "set", self.interface, "down"])
            await self._run_cmd(["iw", "dev", self.interface, "set", "type", "managed"])
            await self._run_cmd(["ip", "link", "set", self.interface, "up"])
        
        await asyncio.sleep(0.5)

    async def _run_cmd(self, cmd: List[str]) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception as e:
            logger.error("Command failed", cmd=cmd, error=str(e))
            return False

    def get_known_networks(self) -> List[NetworkInfo]:
        return list(self._known_networks.values())


class WiFiScanner:
    """High-level WiFi scanner facade for the WiFi module."""

    def __init__(
        self,
        interface: str,
        strategy: ScanStrategy = ScanStrategy.PASSIVE_ONLY,
        output_dir: Optional[str] = None,
    ):
        self.manager = ScanManager(interface, strategy, output_dir)

    async def scan(self, channels: Optional[List[int]] = None, duration: int = 30) -> List[NetworkInfo]:
        """Perform a single scan."""
        return await self.manager.scan(channels, duration)

    async def continuous_scan(
        self,
        interval: int = 30,
        channels: Optional[List[int]] = None,
        callback: Optional[callable] = None,
    ) -> AsyncIterator[List[NetworkInfo]]:
        """Continuously scan and yield results."""
        while True:
            networks = await self.manager.scan(channels=channels, duration=interval)
            if callback:
                callback(networks)
            yield self.manager.get_known_networks()
            await asyncio.sleep(interval)

    def get_known_networks(self) -> List[NetworkInfo]:
        return self.manager.get_known_networks()


# Channel lists for common regions
CHANNELS_2GHZ = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144]
CHANNELS_6GHZ = list(range(1, 234, 4))  # 1, 5, 9, ... 233
ALL_CHANNELS = CHANNELS_2GHZ + CHANNELS_5GHZ + CHANNELS_6GHZ