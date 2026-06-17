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
import structlog
import subprocess
import shutil
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Tuple

from urban_hs.modules.wifi.attacks import BaseAttack, AttackResult, AttackStatus, DeauthAttack

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
    output_dir: str = "/var/lib/urban-hs/wifi_attacks/fragattacks"
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
            "/home/andresantos/fragattacks",
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
            # Run the test
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.fragattacks_path,
            )
            
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), 
                timeout=self.config.attack_timeout
            )
            
            # Parse output
            output = stdout.decode()
            error = stderr.decode()
            
            vulnerable, details = self._parse_output(attack_type, output, error)
            
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=vulnerable,
                details=details,
            )
            
        except asyncio.TimeoutError:
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=False,
                details="Test timed out",
            )
        except Exception as e:
            return FragAttackResult(
                attack_type=attack_type,
                vulnerable=False,
                details=f"Test failed: {str(e)}",
            )

    def _build_command(
        self,
        attack_type: FragAttackType,
        target: str,
        channel: int,
        client_mac: Optional[str],
    ) -> Optional[List[str]]:
        """Build command for fragattacks tool."""
        
        base_cmd = [
            "python3", "fragattacks.py",
            "-i", self.config.monitor_interface or self.config.interface,
            "--channel", str(channel),
            "--target", target,
        ]
        
        if client_mac:
            base_cmd.extend(["--client", client_mac])
        
        # Attack-specific options
        if attack_type == FragAttackType.FRAGMENTATION:
            base_cmd.append("--test-fragmentation")
        elif attack_type == FragAttackType.MIXED_KEY:
            base_cmd.append("--test-mixed-key")
        elif attack_type == FragAttackType.AGGREGATION:
            base_cmd.append("--test-aggregation")
        elif attack_type == FragAttackType.ALL:
            base_cmd.append("--test-all")
        else:
            return None
        
        return base_cmd

    def _parse_output(
        self,
        attack_type: FragAttackType,
        stdout: str,
        stderr: str,
    ) -> Tuple[bool, str]:
        """Parse fragattacks output to determine vulnerability."""
        
        vulnerable = False
        details = ""
        
        # Common indicators in fragattacks output
        if "VULNERABLE" in stdout.upper() or "VULNERABLE" in stderr.upper():
            vulnerable = True
            details = "Tool detected vulnerability"
        elif "NOT VULNERABLE" in stdout.upper() or "NOT VULNERABLE" in stderr.upper():
            vulnerable = False
            details = "Tool reports not vulnerable"
        elif "ERROR" in stdout.upper() or "ERROR" in stderr.upper():
            vulnerable = False
            details = f"Error: {stderr[:500]}"
        else:
            # Parse for specific test results
            lines = stdout.split('\n') + stderr.split('\n')
            for line in lines:
                if attack_type.value.lower() in line.lower():
                    if "PASS" in line.upper() or "SUCCESS" in line.upper() or "VULNERABLE" in line.upper():
                        vulnerable = True
                        details = line.strip()
                        break
                    elif "FAIL" in line.upper() or "NOT VULNERABLE" in line.upper():
                        vulnerable = False
                        details = line.strip()
                        break
            
            if not details:
                details = f"Output: {stdout[:300]}"
        
        return vulnerable, details

    def stop(self):
        """Stop running tests."""
        self._running = False


class FragAttackAttack(BaseAttack):
    """
    FragAttacks integration as a standard WiFi attack.
    
    Wraps the fragattacks tool as a BaseAttack for unified execution.
    """
    
    def __init__(
        self,
        interface: str,
        output_dir: str = "/var/lib/urban-hs/wifi_attacks/fragattacks",
        attack_timeout: int = 180,
        attack_types: Optional[List[FragAttackType]] = None,
        monitor_interface: Optional[str] = None,
    ):
        super().__init__(interface, output_dir, attack_timeout)
        self.attack_types = attack_types or [
            FragAttackType.FRAGMENTATION,
            FragAttackType.MIXED_KEY,
            FragAttackType.AGGREGATION,
        ]
        self.monitor_interface = monitor_interface
        self.wrapper: Optional[FragAttacksWrapper] = None

    async def execute(
        self,
        target_bssid: str,
        target_essid: Optional[str] = None,
        channel: int = 1,
        callback: Optional[Callable[[str], None]] = None,
        **kwargs,
    ) -> AttackResult:
        """Execute FragAttacks test suite."""
        
        client_mac = kwargs.get("client_mac")
        
        result = AttackResult(
            attack_type="fragattacks",
            target_bssid=target_bssid,
            target_essid=target_essid,
            status=AttackStatus.RUNNING,
            started_at=datetime.utcnow(),
            metadata={
                "attack_types": [a.value for a in self.attack_types],
                "client_mac": client_mac,
            },
        )
        
        self._running = True
        
        safe_bssid = target_bssid.replace(":", "_")
        timestamp = int(time.time())
        base_name = f"fragattacks_{target_bssid.replace(':', '_')}_{timestamp}"
        output_dir = self.output_dir / base_name
        output_dir.mkdir(parents=True, exist_ok=True)
        
        result.output_files = [str(output_dir)]
        
        try:
            # Initialize wrapper
            config = FragAttackConfig(
                interface=self.interface,
                monitor_interface=self.monitor_interface,
                output_dir=str(output_dir),
                attack_timeout=self.attack_timeout,
                attack_types=self.attack_types,
                target_bssid=target_bssid,
                target_essid=target_essid,
                channel=channel,
                client_mac=client_mac,
            )
            
            self.wrapper = FragAttacksWrapper(config)
            # Store tool location in wrapper
            self.wrapper._find_fragattacks()
            
            # Run tests
            test_results = await self.wrapper.run_tests(
                target_bssid=target_bssid,
                target_essid=target_essid,
                channel=channel,
                client_mac=client_mac,
                callback=callback,
            )
            
            result.metadata["test_results"] = [
                {
                    "type": r.attack_type.value,
                    "vulnerable": r.vulnerable,
                    "details": r.details,
                    "timestamp": r.timestamp.isoformat(),
                }
                for r in test_results
            ]
            
            # Overall status
            any_vulnerable = any(r.vulnerable for r in test_results)
            if any_vulnerable:
                result.status = AttackStatus.SUCCESS
                result.metadata["overall"] = "VULNERABLE to one or more FragAttacks"
                self._notify_callback(callback, "FragAttacks: VULNERABLE - One or more tests found vulnerabilities")
            else:
                result.status = AttackStatus.FAILED
                result.metadata["overall"] = "Not vulnerable to tested FragAttacks"
                self._notify_callback(callback, "FragAttacks: Not vulnerable to tested attacks")
            
            result.finished_at = datetime.utcnow()
            
        except Exception as e:
            result.status = AttackStatus.FAILED
            result.error_message = str(e)
            self._log("FragAttacks test failed", error=str(e))
        finally:
            self._running = False
        
        return result


# ============================================================
# Convenience Functions
# ============================================================

async def run_fragattacks(
    target_bssid: str,
    target_essid: Optional[str] = None,
    channel: int = 1,
    client_mac: Optional[str] = None,
    attack_types: Optional[List[FragAttackType]] = None,
    interface: str = "wlan0",
    monitor_interface: Optional[str] = None,
    output_dir: str = "/var/lib/urban-hs/wifi_attacks/fragattacks",
) -> List[FragAttackResult]:
    """Convenience function to run FragAttacks tests."""
    
    config = FragAttackConfig(
        interface=interface,
        monitor_interface=monitor_interface,
        output_dir=output_dir,
        attack_types=attack_types,
        target_bssid=target_bssid,
        target_essid=target_essid,
        channel=channel,
        client_mac=client_mac,
    )
    
    wrapper = FragAttacksWrapper(config)
    return await wrapper.run_tests(
        target_bssid=target_bssid,
        target_essid=target_essid,
        channel=channel,
        client_mac=client_mac,
    )


# ============================================================
# Exports
# ============================================================

__all__ = [
    "FragAttackType",
    "FragAttackConfig",
    "FragAttackResult",
    "FragAttacksWrapper",
    "FragAttackAttack",
    "run_fragattacks",
]