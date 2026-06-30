"""
WiFi Managers - Handshake management, MAC changing, Geo mapping.
"""

import asyncio
import json
import os
import shutil
import structlog
import subprocess
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

logger = structlog.get_logger(__name__)


@dataclass
class HandshakeInfo:
    """Information about a captured handshake."""
    id: str
    bssid: str
    essid: Optional[str]
    capture_path: str
    hash_path: Optional[str]
    hashcat_mode: int  # 22000 for PMKID, 2500 for WPA
    crack_status: str = "uncracked"  # uncracked, cracked, failed, in_progress
    password: Optional[str] = None
    cracked_at: Optional[datetime] = None
    capture_time: datetime = field(default_factory=datetime.utcnow)
    gps_lat: Optional[float] = None
    gps_lon: Optional[float] = None
    vendor: Optional[str] = None
    signal_dbm: int = -100
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "bssid": self.bssid,
            "essid": self.essid,
            "capture_path": self.capture_path,
            "hash_path": self.hash_path,
            "hashcat_mode": self.hashcat_mode,
            "crack_status": self.crack_status,
            "password": self.password,
            "cracked_at": self.cracked_at.isoformat() if self.cracked_at else None,
            "capture_time": self.capture_time.isoformat(),
            "gps_lat": self.gps_lat,
            "gps_lon": self.gps_lon,
            "vendor": self.vendor,
            "signal_dbm": self.signal_dbm,
            "metadata": self.metadata,
        }


class HandshakeManager:
    """
    Manages captured handshakes and PMKIDs.
    
    Features:
    - Deduplication (by BSSID+ESSID)
    - Hashcat integration for cracking
    - Export to WiGLE, Kismet, Hashcat formats
    - Crack tracking and reporting
    """

    def __init__(
        self,
        handshake_dir: Optional[str] = None,
        hash_dir: Optional[str] = None,
        cracked_dir: Optional[str] = None,
    ):
        if handshake_dir is None or hash_dir is None or cracked_dir is None:
            from urban_hs.core.config import get_config
            cfg = get_config()
            if handshake_dir is None:
                handshake_dir = str(Path(cfg.storage.resolve_wifi_attacks_dir()) / "handshakes")
            if hash_dir is None:
                hash_dir = str(Path(cfg.storage.resolve_hashes_dir()))
            if cracked_dir is None:
                cracked_dir = str(Path(cfg.storage.resolve_wifi_attacks_dir()) / "cracked")
        self.handshake_dir = Path(handshake_dir)
        self.hash_dir = Path(hash_dir)
        self.cracked_dir = Path(cracked_dir)
        
        for d in [self.handshake_dir, self.hash_dir, self.cracked_dir]:
            d.mkdir(parents=True, exist_ok=True)

        self._handshakes: Dict[str, HandshakeInfo] = {}
        self._load_existing()

    def _load_existing(self) -> None:
        """Load existing handshakes from disk."""
        for hash_file in self.hash_dir.glob("*.22000"):
            try:
                handshake = self._parse_hash_file(hash_file)
                if handshake:
                    self._handshakes[handshake.id] = handshake
            except Exception as e:
                logger.warning("Failed to load handshake", file=hash_file, error=str(e))

    def _parse_hash_file(self, hash_file: Path) -> Optional[HandshakeInfo]:
        """Parse hashcat 22000 file to extract handshake info."""
        try:
            with open(hash_file, 'r') as f:
                line = f.readline().strip()
            
            if not line:
                return None

            # Parse hccapx/22000 format
            parts = line.split('*')
            if len(parts) < 6:
                return None

            # Extract BSSID, ESSID from hash
            # Format: WPA*PMKID*version*ESSID_len*ESSID*bssid*...
            # This is simplified - real parsing is more complex
            
            handshake_id = hash_file.stem
            
            return HandshakeInfo(
                id=handshake_id,
                bssid="",  # Would parse from hash
                essid=None,
                capture_path="",
                hash_path=str(hash_file),
                hashcat_mode=22000,
            )
        except Exception:
            return None

    def add_handshake(
        self,
        bssid: str,
        essid: Optional[str],
        capture_path: str,
        hash_path: Optional[str] = None,
        hashcat_mode: int = 22000,
        gps_lat: Optional[float] = None,
        gps_lon: Optional[float] = None,
        vendor: Optional[str] = None,
        signal_dbm: int = -100,
    ) -> HandshakeInfo:
        """Add or update a handshake record."""
        # Create unique key
        key = f"{bssid.replace(':', '_')}_{essid or 'hidden'}"
        
        if key in self._handshakes:
            # Update existing
            existing = self._handshakes[key]
            if hash_path:
                existing.hash_path = hash_path
                existing.hashcat_mode = hashcat_mode
            return existing

        handshake = HandshakeInfo(
            id=str(uuid.uuid4())[:8],
            bssid=bssid,
            essid=essid,
            capture_path="",
            hash_path=hash_path,
            hashcat_mode=hashcat_mode,
            gps_lat=gps_lat,
            gps_lon=gps_lon,
            vendor=vendor,
        )
        
        self._handshakes[key] = handshake
        return handshake

    def get_handshake(self, bssid: str, essid: Optional[str] = None) -> Optional[HandshakeInfo]:
        """Get handshake by BSSID and optional ESSID."""
        key = f"{bssid.replace(':', '_')}_{essid or 'hidden'}"
        return self._handshakes.get(key)

    def list_handshakes(
        self,
        status: Optional[str] = None,
        hashcat_mode: Optional[int] = None,
    ) -> List[HandshakeInfo]:
        """List handshakes with optional filters."""
        results = list(self._handshakes.values())
        
        if status:
            results = [h for h in results if h.crack_status == status]
        if hashcat_mode:
            results = [h for h in results if h.hashcat_mode == hashcat_mode]
        
        return sorted(results, key=lambda h: h.capture_time, reverse=True)

    def mark_cracked(self, handshake_id: str, password: str) -> bool:
        """Mark a handshake as cracked."""
        handshake = self._handshakes.get(handshake_id)
        if handshake:
            handshake.crack_status = "cracked"
            handshake.password = password
            handshake.cracked_at = datetime.utcnow()
            
            # Move to cracked directory
            if handshake.hash_path:
                src = Path(handshake.hash_path)
                dst = self.cracked_dir / (src.stem + "_CRACKED" + src.suffix)
                shutil.move(str(src), str(dst))
                handshake.hash_path = str(dst)
            
            return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about captured handshakes."""
        total = len(self._handshakes)
        cracked = len([h for h in self._handshakes.values() if h.crack_status == "cracked"])
        uncracked = total - cracked
        
        by_mode: Dict[int, int] = {}
        for h in self._handshakes.values():
            by_mode[h.hashcat_mode] = by_mode.get(h.hashcat_mode, 0) + 1
        
        return {
            "total": total,
            "cracked": cracked,
            "uncracked": uncracked,
            "by_mode": by_mode,
        }

    # Export functions
    def export_hashcat(self, output_file: Path, status: Optional[str] = None) -> int:
        """Export hashes in hashcat format."""
        count = 0
        with open(output_file, 'w') as f:
            for h in self._handshakes.values():
                if status and h.crack_status != status:
                    continue
                if h.hash_path and Path(h.hash_path).exists():
                    with open(h.hash_path) as src:
                        f.write(src.read())
                    count += 1
        return count

    def export_wigle_csv(self, output_file: Path) -> int:
        """Export to WiGLE CSV format."""
        count = 0
        with open(output_file, 'w') as f:
            f.write("WigleWifi-1.6,appRelease=2.55,model=UrbanHS,release=3.0.0,device=Pi5,display=UrbanHS,board=RaspberryPi,brand=UrbanHS\n")
            f.write("MAC,SSID,AuthMode,FirstSeen,Channel,RSSI,CurrentLatitude,CurrentLongitude,AltitudeMeters,AccuracyMeters,Type\n")
            
            for h in self._handshakes.values():
                if h.gps_lat is not None and h.gps_lon is not None:
                    line = f"{h.bssid},{h.essid or ''},,{h.capture_time.isoformat()},{h.metadata.get('channel', '')},{h.metadata.get('signal_dbm', '')},{h.gps_lat},{h.gps_lon},,,WIFI\n"
                    f.write(line)
                    count += 1
        return count

    def export_kismet_netxml(self, output_file: Path) -> int:
        """Export to Kismet netxml format."""
        # Implementation would generate proper netxml
        # Simplified for now
        return 0


class MACChanger:
    """
    MAC Address Changer with OUI profiles.
    
    Features:
    - Random MAC with vendor OUI
    - Predefined profiles (Apple, Samsung, Intel, etc.)
    - Persistent profiles across reboots
    """

    # Common vendor OUIs
    OUI_PROFILES = {
        "apple": [
            "00:1A:2B", "00:1B:63", "00:1C:B3", "00:1D:4F", "00:1E:52",
            "00:1F:3C", "00:21:E9", "00:22:41", "00:23:6C", "00:24:36",
            "00:25:00", "00:26:08", "00:26:B0", "00:27:BC", "00:17:F2",
            "00:1C:B3", "00:1D:4F", "00:1E:52", "00:1F:3C", "00:21:E9",
            "28:CF:E9", "28:E0:2C", "28:F0:76", "3C:07:54", "3C:15:C2",
            "40:A6:D9", "40:E4:6D", "44:8A:5B", "44:D8:84", "48:60:BC",
            "4C:8D:79", "50:ED:3C", "54:9D:80", "58:55:CA", "5C:95:AE",
            "60:03:08", "64:9E:F3", "68:5B:35", "68:96:7B", "6C:40:08",
            "6C:70:9F", "6C:FF:BE", "70:73:CB", "74:81:14", "74:E1:B6",
            "78:31:C1", "78:4F:43", "78:CA:39", "7C:11:BE", "7C:6D:62",
            "80:92:9F", "84:38:35", "84:8A:8D", "88:53:95", "88:63:DF",
            "8C:58:77", "8C:85:90", "90:27:E4", "94:35:0A", "98:01:A7",
            "9C:04:EB", "A0:99:9B", "A4:5E:60", "A4:83:E7", "A8:20:66",
            "A8:66:7F", "AC:3B:77", "AC:87:A3", "B0:34:95", "B0:65:BD",
            "B4:18:D1", "B8:09:8A", "B8:8D:12", "BC:52:B7", "C0:1C:30",
            "C0:3F:0E", "C4:2C:03", "C8:69:CD", "CC:25:EF", "CC:3D:82",
            "D0:23:DB", "D4:0B:1A", "D4:9A:20", "D8:30:62", "D8:97:BA",
            "DC:2B:61", "E0:5F:FE", "E4:8B:7F", "E8:1D:1D", "E8:6E:D4",
            "EC:35:86", "F0:18:98", "F4:0F:24", "F8:1E:DF", "FC:25:3F",
        ],
        "samsung": [
            "00:12:47", "00:14:51", "00:15:99", "00:15:AF", "00:16:32",
            "00:17:E2", "00:19:7D", "00:1A:4D", "00:1B:98", "00:1C:26",
            "00:1D:25", "00:1E:58", "00:21:0E", "00:21:3A", "00:22:43",
            "00:23:69", "00:24:54", "00:25:60", "00:26:5B", "00:27:10",
            "00:21:87", "00:22:5F", "00:23:51", "00:24:08", "00:25:4B",
            "28:ED:6A", "2C:4D:54", "30:10:B3", "34:BD:FA", "38:83:45",
            "3C:78:4C", "40:A5:EF", "44:8A:5B", "48:FF:8A", "50:85:69",
            "54:F2:01", "5C:F3:70", "60:38:0E", "64:00:6A", "68:17:29",
            "70:7E:43", "74:6F:F9", "78:F8:82", "7C:49:4E", "80:E6:50",
            "84:EB:18", "88:79:7E", "8C:34:FD", "90:72:40", "94:7B:E7",
            "98:FE:94", "9C:2F:9B", "A0:18:28", "A4:38:CC", "A8:0E:3D",
            "AC:27:1E", "B0:98:90", "B4:DF:82", "B8:F1:86", "BC:5F:F4",
            "C0:74:AD", "C4:D9:87", "C8:34:FD", "CC:5D:4E", "D0:81:7A",
        ],
        "intel": [
            "00:13:02", "00:15:00", "00:16:6F", "00:19:D1", "00:1B:77",
            "00:1C:23", "00:21:5C", "00:22:FA", "00:23:14", "00:24:D6",
            "00:26:C6", "00:27:10", "00:1D:E0", "00:1E:64", "00:1F:3A",
            "00:21:6A", "00:22:FA", "00:23:AE", "00:24:D7", "00:26:B6",
            "00:27:10", "3C:A9:F4", "40:16:3A", "44:85:00", "48:4D:7E",
            "4C:34:88", "50:7B:9D", "54:AB:3A", "58:00:E3", "5C:E9:1E",
            "60:57:18", "64:00:6A", "68:05:CA", "70:85:C2", "74:E5:43",
            "80:19:34", "84:A6:C8", "88:53:2E", "8C:70:5A", "90:48:9A",
            "94:65:9C", "98:5F:D4", "9C:B6:D0", "A0:8C:FD", "A4:4E:31",
            "A8:15:4D", "AC:BC:32", "B0:6E:BF", "B4:E6:2D", "B8:08:CF",
            "BC:F6:85", "C0:38:96", "C4:46:19", "C8:9C:DC", "CC:2D:E0",
            "D0:57:7C", "D4:81:D7", "D8:63:75", "DC:41:59", "E0:3F:49",
            "E4:F8:9C", "E8:2A:EA", "EC:0E:C4", "F0:1F:AF", "F4:2A:1C",
            "F8:1A:67", "FC:AA:14",
        ],
        "realtek": [
            "00:E0:4C", "00:E0:58", "00:E0:4C", "00:1A:4D", "00:1B:98",
            "00:1C:26", "00:1D:25", "00:1E:58", "00:1F:3A", "00:20:7B",
            "00:21:3A", "00:22:43", "00:23:69", "00:24:54", "00:25:60",
            "00:26:5B", "00:27:10", "28:ED:6A", "2C:4D:54", "30:10:B3",
            "34:BD:FA", "38:83:45", "3C:78:4C", "40:A5:EF", "44:8A:5B",
            "48:FF:8A", "50:85:69", "54:F2:01", "5C:F3:70", "60:38:0E",
            "64:00:6A", "68:17:29", "70:7E:43", "74:6F:F9", "78:F8:82",
            "7C:49:4E", "80:E6:50", "84:EB:18", "88:79:7E", "8C:34:FD",
            "90:72:40", "94:7B:E7", "98:FE:94", "9C:2F:9B", "A0:18:28",
            "A4:38:CC", "A8:0E:3D", "AC:27:1E", "B0:98:90", "B4:DF:82",
            "B8:F1:86", "BC:5F:F4", "C0:74:AD", "C4:D9:87", "C8:34:FD",
        ],
        "atheros": [
            "00:03:7F", "00:11:F5", "00:13:E8", "00:15:6D", "00:16:E6",
            "00:18:39", "00:19:E0", "00:1B:63", "00:1C:B3", "00:1D:4F",
            "00:1E:52", "00:1F:3C", "00:21:E9", "00:22:41", "00:23:6C",
            "00:24:36", "00:25:00", "00:26:08", "00:26:B0", "00:27:BC",
            "28:CF:E9", "28:E0:2C", "28:F0:76", "3C:07:54", "3C:15:C2",
            "40:A6:D9", "40:E4:6D", "44:8A:5B", "44:D8:84", "48:60:BC",
            "4C:8D:79", "50:ED:3C", "54:9D:80", "58:55:CA", "5C:95:AE",
            "60:03:08", "64:9E:F3", "68:5B:35", "68:96:7B", "6C:40:08",
        ],
        "random": None,  # Fully random
    }

    def __init__(self, interface: str):
        self.interface = interface
        self.current_mac: Optional[str] = None
        self.original_mac: Optional[str] = None

    def get_current_mac(self) -> Optional[str]:
        """Get current MAC address of interface."""
        try:
            result = subprocess.run(
                ["ip", "link", "show", self.interface],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if "link/ether" in line:
                    return line.strip().split()[1]
        except Exception as e:
            logger.error("Failed to get MAC", error=str(e))
        return None

    def save_original_mac(self) -> None:
        """Save the original MAC for later restoration."""
        self.original_mac = self.get_current_mac()
        logger.info("Original MAC saved", mac=self.original_mac)

    def restore_original_mac(self) -> bool:
        """Restore the original MAC address."""
        if self.original_mac:
            return self.set_mac(self.original_mac)
        return False

    def set_mac(self, mac: str) -> bool:
        """Set a specific MAC address."""
        try:
            # Bring interface down
            subprocess.run(["ip", "link", "set", self.interface, "down"], check=True, timeout=10)
            
            # Set MAC
            subprocess.run(["macchanger", "-m", mac, self.interface], check=True, timeout=10)
            
            # Bring interface up
            subprocess.run(["ip", "link", "set", self.interface, "up"], check=True, timeout=10)
            
            self.current_mac = mac
            logger.info("MAC changed", interface=self.interface, mac=mac)
            return True
        except subprocess.CalledProcessError as e:
            logger.error("Failed to change MAC", error=str(e))
            return False
        except Exception as e:
            logger.error("MAC change error", error=str(e))
            return False

    def randomize_mac(self, profile: str = "random") -> Optional[str]:
        """Generate and set a random MAC with optional vendor profile."""
        if profile == "random" or profile not in self.OUI_PROFILES:
            # Fully random MAC
            import random
            mac = "02:" + ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(5))
        else:
            # Use vendor OUI + random suffix
            import random
            oui_list = self.OUI_PROFILES[profile]
            oui = random.choice(oui_list)
            suffix = ":".join(f"{random.randint(0x00, 0xFF):02x}" for _ in range(3))
            mac = f"{oui}:{suffix}"

        if self.set_mac(mac):
            return mac
        return None

    def get_current_vendor(self) -> Optional[str]:
        """Identify vendor from current MAC."""
        mac = self.get_current_mac()
        if not mac:
            return None
        
        oui = mac[:8].upper()
        for vendor, ouis in self.OUI_PROFILES.items():
            if isinstance(ouis, list) and any(mac.startswith(oui) for oui in ouis):
                return vendor
        return "unknown"

    def list_profiles(self) -> Dict[str, int]:
        """List available profiles with OUI counts."""
        return {k: len(v) if v else 0 for k, v in self.OUI_PROFILES.items()}


class GeoMapper:
    """
    GPS integration for wardriving.
    
    Integrates with gpsd for real-time position.
    Exports to Kismet, WiGLE, Google Earth formats.
    """

    def __init__(self, gpsd_host: str = "localhost", gpsd_port: int = 2947):
        self.gpsd_host = gpsd_host
        self.gpsd_port = gpsd_port
        self._gps_data: Dict[str, Any] = {}
        self._running = False
        self._reader_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Start GPS data reader."""
        self._running = True
        self._reader_task = asyncio.create_task(self._read_gpsd())

    async def stop(self) -> None:
        """Stop GPS reader."""
        self._running = False
        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

    async def _read_gpsd(self) -> None:
        """Read GPS data from gpsd."""
        import socket
        import json

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.gpsd_host, self.gpsd_port))
            sock.send(b'?WATCH={"enable":true,"json":true}\n')
            
            buffer = b""
            while self._running:
                data = sock.recv(4096)
                if not data:
                    break
                
                buffer += data
                lines = buffer.split(b'\n')
                buffer = lines[-1]
                
                for line in lines[:-1]:
                    try:
                        data = json.loads(line.decode())
                        if data.get("class") == "TPV":
                            self._gps_data = {
                                "lat": data.get("lat"),
                                "lon": data.get("lon"),
                                "alt": data.get("alt"),
                                "speed": data.get("speed"),
                                "track": data.get("track"),
                                "time": data.get("time"),
                                "mode": data.get("mode"),
                                "epx": data.get("epx"),
                                "epy": data.get("epy"),
                            }
                    except json.JSONDecodeError:
                        pass
                        
        except Exception as e:
            logger.error("GPS read error", error=str(e))
        finally:
            try:
                sock.close()
            except Exception:
                pass

    def get_position(self) -> Optional[Dict[str, float]]:
        """Get current GPS position."""
        if self._gps_data.get("lat") is not None and self._gps_data.get("lon") is not None:
            return {
                "lat": self._gps_data["lat"],
                "lon": self._gps_data["lon"],
                "alt": self._gps_data.get("alt"),
                "accuracy": max(
                    self._gps_data.get("epx", 0),
                    self._gps_data.get("epy", 0)
                ),
            }
        return None

    def is_fixed(self) -> bool:
        """Check if GPS has a valid fix (mode >= 2)."""
        return self._gps_data.get("mode", 0) >= 2

    def get_gps_data(self) -> Dict[str, Any]:
        return dict(self._gps_data)