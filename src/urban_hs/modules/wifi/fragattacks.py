"""
FragAttacks Wrapper - CVE-2020-24586 / CVE-2020-24587 / CVE-2020-24588

Wrapper for Mathy Vanhoef's fragattacks tool.
Tests for WiFi fragmentation and mixed key vulnerabilities.

CVE-2020-24586: Fragmentation attack (frame reassembly)
CVE-2020-24587: Mixed key attack (replay of fragmented frames)
CVE-2020-24588: Frame aggregation attack (a-MSDU)

Ref: https://www.fragattacks.com/
Tool: https://github.com/vanhoefm/fragattacks
"""

import asyncio
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Callable, List, Optional

import structlog

logger = structlog.get_logger(__name__)


class FragAttackType(Enum):
    """Types of FragAttacks to test."""
    FRAGMENTATION = "fragmentation"      # CVE-2020-24586
    MIXED_KEY = "mixed_key"              # CVE-2020-24587
    AGGREGATION = "aggregation"          # CVE-2020-24588
    ALL = "all"


@dataclass
class FragAttackConfig:
    """Configuration for FragAttacks."""
    interface: str = "wlan0"
    monitor_interface: Optional[str] = None
    output_dir: Optional[str] = None
    attack_timeout: int = 120
    attack_types: Optional[List[FragAttackType]] = None
    target_bssid: str = ""
    target_essid: Optional[str] = None
    channel: int = 1
    client_mac: Optional[str] = None
    fragattacks_path: Optional[str] = None  # Path to fragattacks repo


@dataclass
class FragAttackResult:
    """Result of FragAttacks test."""
    attack_type: FragAttackType
    vulnerable: bool
    details: str = ""
    affected_frames: int = 0
    timestamp: datetime = field(default_factory=datetime.utcnow)


class FragAttacksWrapper:
    """
    Wrapper for fragattacks tool by Mathy Vanhoef.

    Tests for:
    - CVE-2020-24586: Fragmentation attack (reassembly of non-existent fragments)
    - CVE-2020-24587: Mixed key attack (replay of fragmented frames with different keys)
    - CVE-2020-24588: Frame aggregation attack (a-MSDU without authentication)

    Usage:
        wrapper = FragAttacksWrapper(config)
        results = await wrapper.run_tests(target_bssid, target_essid, channel)
    """

    def __init__(self, config: FragAttackConfig):
        if config.output_dir is None:
            from urban_hs.core.config import get_config
            config.output_dir = str(Path(get_config().storage.resolve_wifi_attacks_dir()) / "fragattacks")
        self.config = config
        self.results: List[FragAttackResult] = []
        self._running = False

        # Find fragattacks installation
        self.fragattacks_path = self._find_fragattacks()

        if not self.fragattacks_path:
            logger.warning("fragattacks tool not found. Install from https://github.com/vanhoefm/fragattacks")

    def _find_fragattacks(self) -> Optional[str]:
        """Find fragattacks installation."""
        # Check configured path
        if self.config.fragattacks_path and Path(self.config.fragattacks_path).exists():
            return self.config.fragattacks_path

        # Check common locations
        paths = [
            "/opt/fragattacks",
            "/usr/local/fragattacks",
            os.path.expanduser("~/fragattacks"),
        ]

        for p in paths:
            if Path(p).exists() and (Path(p) / "fragattacks.py").exists():
                return p

        # Check if available in PATH
        if shutil.which("fragattacks"):
            # Try to find the actual script location
            result = subprocess.run(["which", "fragattacks"], capture_output=True, text=True)
            if result.stdout:
                return str(Path(result.stdout.strip()).parent)

        return None

    async def _check_chipset_compatibility(self) -> bool:
        """Check if the current WiFi adapter supports the required chipset for FragAttacks.

        Vanhoef's fragattacks tool requires Cypress/Cypress chipset (e.g., CYW43438, CYW43455).
        Broadcom and other chipsets are not compatible.
        """
        try:
            # Get phy info for the interface
            interface = self.config.monitor_interface or self.config.interface
            result = await asyncio.create_subprocess_exec(
                "iw", "dev", interface, "info",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await result.communicate()
            output = stdout.decode()

            # Check for Cypress chipset identifiers
            # Cypress chips typically show "cypress" or "brcmfmac" with specific models
            cypress_indicators = [
                "cypress",
                "cyw43438",
                "cyw43455",
                "cyw43456",
                "cyw4354",
                "cyw4356",
                "cyw4345",
                "cyw4349",
                "brcmfmac",  # Broadcom FullMAC - some Cypress chips use this
            ]

            output_lower = output.lower()
            for indicator in cypress_indicators:
                if indicator in output_lower:
                    logger.info("Compatible Cypress chipset detected", interface=interface, indicator=indicator)
                    return True

            # Check driver
            if "brcmfmac" in output_lower:
                # Some Pi WiFi uses brcmfmac but may not be Cypress
                logger.warning("Broadcom brcmfmac driver detected - may not be compatible with fragattacks (requires Cypress)")

            logger.warning("No compatible Cypress chipset detected for fragattacks. Tool requires Cypress chipset (CYW43438, CYW43455, etc.)")
            return False

        except Exception as e:
            logger.warning("Could not check chipset compatibility", error=str(e))
            return False

    async def run_tests(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        client_mac: Optional[str] = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> List[FragAttackResult]:
        """
        Run all configured FragAttacks tests.

        Returns list of results for each attack type.
        """
        self._running = True
        self.results = []

        # Check chipset compatibility first
        compatible = await self._check_chipset_compatibility()
        if not compatible:
            logger.warning("Skipping FragAttacks - incompatible chipset")
            self._running = False
            return [FragAttackResult(
                attack_type=at,
                vulnerable=False,
                details="Incompatible chipset - FragAttacks requires Cypress chipset (CYW43438, CYW43455, etc.)",
            ) for at in (self.config.attack_types or [FragAttackType.FRAGMENTATION, FragAttackType.MIXED_KEY, FragAttackType.AGGREGATION])]

        attack_types = self.config.attack_types or [
            FragAttackType.FRAGMENTATION,
            FragAttackType.MIXED_KEY,
            FragAttackType.AGGREGATION,
        ]

        for attack_type in attack_types:
            if not self._running:
                break

            if callback:
                callback(f"Running FragAttack: {attack_type.value}")

            result = await self._run_single_test(
                attack_type=attack_type,
                target_bssid=target_bssid,
                target_essid=target_essid,
                channel=channel,
                client_mac=client_mac,
                callback=callback,
            )

            self.results.append(result)

            if callback:
                status = "VULNERABLE" if result.vulnerable else "NOT VULNERABLE"
                callback(f"  {attack_type.value}: {status} - {result.details}")

        self._running = False
        return self.results

    async def _run_single_test(
        self,
        attack_type: FragAttackType,
        target_bssid: str,
        target_essid: Optional[str],
        channel: int,
        client_mac: Optional[str],
        callback: Optional[Callable[[str], None]],
    ) -> FragAttackResult:
        """Run a single FragAttack test."""

        if not self.fragattacks_path:
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=False,
                details="fragattacks tool not installed",
            )

        # Build target specification
        target = target_bssid
        if target_essid:
            target = f"{target_bssid},{target_essid}"

        # Build command based on attack type
        cmd = self._build_command(attack_type, target, channel, client_mac)

        if not cmd:
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=False,
                details="Invalid attack type",
            )

        try:
            # Run the command
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=self.config.attack_timeout,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return FragAttackResult(
                    attack_type=attack_type,
                    vulnerable=False,
                    details=f"Timeout after {self.config.attack_timeout}s",
                )

            stdout_text = stdout.decode()
            stderr_text = stderr.decode()

            # Parse results
            vulnerable = self._parse_result(stdout_text, attack_type)
            details = self._extract_details(stdout_text, stderr_text, attack_type)

            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=vulnerable,
                details=details,
                affected_frames=0,  # TODO: parse from output
            )

        except Exception as e:
            logger.error("FragAttack test failed", attack_type=attack_type.value, error=str(e))
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=False,
                details=f"Error: {str(e)}",
            )

    def _build_command(
        self,
        attack_type: FragAttackType,
        target: str,
        channel: int,
        client_mac: Optional[str],
    ) -> Optional[List[str]]:
        """Build command for fragattacks tool."""
        if not self.fragattacks_path:
            return None

        script = "fragattacks.py"
        script_path = Path(self.fragattacks_path) / script

        if not script_path.exists():
            return None

        base_cmd = ["python3", str(script_path)]

        if attack_type == FragAttackType.FRAGMENTATION:
            base_cmd.extend(["--attack", "fragmentation"])
        elif attack_type == FragAttackType.MIXED_KEY:
            base_cmd.extend(["--attack", "mixed_key"])
        elif attack_type == FragAttackType.AGGREGATION:
            base_cmd.extend(["--attack", "aggregation"])
        else:
            return None

        base_cmd.extend(["--target", target])
        base_cmd.extend(["--channel", str(channel)])

        return base_cmd

    def _parse_result(self, output: str, attack_type: FragAttackType) -> bool:
        """Parse tool output to determine vulnerability."""
        output_lower = output.lower()
        if "vulnerable" in output_lower or "success" in output_lower:
            return True
        return False

    def _extract_details(self, stdout: str, stderr: str, attack_type: FragAttackType) -> str:
        """Extract human-readable details from tool output."""
        lines = stdout.strip().split('\n')
        # Return last few meaningful lines
        meaningful = [l for l in lines if l.strip() and not l.startswith('[')]
        return '; '.join(meaningful[-3:]) if meaningful else stderr.strip()[:500]

    def stop(self):
        """Stop any running tests."""
        self._running = False


async def scan_fragattacks_targets(
    interface: str = "wlan0",
    channel: int = 1,
    callback: Optional[Callable[[str], None]] = None,
) -> List[str]:
    """Scan for targets vulnerable to FragAttacks using wireless scan."""
    # This would integrate with WiFi scanner to find WPA2/WPA3 networks
    return []


# ============================================================
# Exports
# ============================================================

__all__ = [
    "FragAttackType",
    "FragAttackConfig",
    "FragAttackResult",
    "FragAttacksWrapper",
    "scan_fragattacks_targets",
]