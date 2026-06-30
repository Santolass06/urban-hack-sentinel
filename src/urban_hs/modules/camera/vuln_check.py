"""
Camera Vulnerability Checker - CVE mapping, exploit availability, and exploit execution.

Provides:
- CVE database for known camera vulnerabilities
- Exploit availability checking
- Automated exploit execution via Nuclei/Metasploit
- Vulnerability verification
"""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

import structlog

from urban_hs.modules.exploit.runner import ExploitRunner, ExploitSource, ExploitTarget
from urban_hs.modules.network import NucleiRunner

logger = structlog.get_logger(__name__)


class VulnStatus(Enum):
    """Vulnerability status."""
    UNKNOWN = "unknown"
    POTENTIALLY_VULNERABLE = "potentially_vulnerable"
    CONFIRMED_VULNERABLE = "confirmed_vulnerable"
    NOT_VULNERABLE = "not_vulnerable"
    PATCHED = "patched"
    EXPLOITED = "exploited"


@dataclass
class CameraVulnerability:
    """Camera vulnerability information."""
    cve_id: str
    name: str
    description: str
    manufacturer: str
    models_affected: List[str] = field(default_factory=list)
    firmware_versions_affected: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    severity: str = "unknown"  # critical, high, medium, low, info
    exploit_available: bool = False
    exploit_path: Optional[str] = None
    metasploit_module: Optional[str] = None
    nuclei_template: Optional[str] = None
    references: List[str] = field(default_factory=list)
    status: VulnStatus = VulnStatus.UNKNOWN
    verified_at: Optional[datetime] = None
    proof: Dict[str, Any] = field(default_factory=dict)


class CameraVulnChecker:
    """
    Camera vulnerability checker with CVE database and exploit verification.
    
    Features:
    - Local CVE database for known camera vulnerabilities
    - Nuclei template integration for automated scanning
    - Metasploit module mapping
    - Exploit verification and proof collection
    - Firmware version matching
    """

    def __init__(
        self,
        cve_db_path: Optional[str] = None,
        nuclei_runner: Optional[NucleiRunner] = None,
        exploit_runner: Optional[ExploitRunner] = None,
    ):
        self.cve_db = self._load_cve_db(cve_db_path) if cve_db_path else DEFAULT_CVE_DB
        self.nuclei = nuclei_runner or NucleiRunner()
        self.exploit_runner = exploit_runner or ExploitRunner()
        
        # Build lookup indices
        self._by_cve: Dict[str, CameraVulnerability] = {v.cve_id: v for v in self.cve_db}
        self._by_manufacturer: Dict[str, List[CameraVulnerability]] = {}
        for vuln in self.cve_db:
            self._by_manufacturer.setdefault(vuln.manufacturer.lower(), []).append(vuln)

    def _load_cve_db(self, path: str) -> List[CameraVulnerability]:
        """Load CVE database from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
            return [CameraVulnerability(**v) for v in data]
        except Exception as e:
            logger.error("Failed to load CVE database", path=path, error=str(e))
            return []

    def save_cve_db(self, path: str):
        """Save CVE database to JSON file."""
        try:
            data = [self._vuln_to_dict(v) for v in self.cve_db]
            with open(path, 'w') as f:
                json.dump(data, f, indent=2, default=str)
        except Exception as e:
            logger.error("Failed to save CVE database", path=path, error=str(e))

    def _vuln_to_dict(self, vuln: CameraVulnerability) -> Dict[str, Any]:
        """Convert vulnerability to dictionary."""
        return {
            "cve_id": vuln.cve_id,
            "name": vuln.name,
            "description": vuln.description,
            "manufacturer": vuln.manufacturer,
            "models_affected": vuln.models_affected,
            "firmware_versions_affected": vuln.firmware_versions_affected,
            "cvss_score": vuln.cvss_score,
            "severity": vuln.severity,
            "exploit_available": vuln.exploit_available,
            "exploit_path": vuln.exploit_path,
            "metasploit_module": vuln.metasploit_module,
            "nuclei_template": vuln.nuclei_template,
            "references": vuln.references,
            "status": vuln.status.value,
            "verified_at": vuln.verified_at.isoformat() if vuln.verified_at else None,
            "proof": vuln.proof,
        }

    # ============================================================
    # Vulnerability Lookup
    # ============================================================

    def get_by_cve(self, cve_id: str) -> Optional[CameraVulnerability]:
        """Get vulnerability by CVE ID."""
        return self._by_cve.get(cve_id.upper())

    def get_by_manufacturer(self, manufacturer: str) -> List[CameraVulnerability]:
        """Get vulnerabilities for manufacturer."""
        return self._by_manufacturer.get(manufacturer.lower(), [])

    def get_by_model(self, manufacturer: str, model: str) -> List[CameraVulnerability]:
        """Get vulnerabilities for specific model."""
        vulns = self.get_by_manufacturer(manufacturer)
        return [
            v for v in vulns
            if not v.models_affected or model.lower() in [m.lower() for m in v.models_affected]
        ]

    def get_by_firmware(self, manufacturer: str, firmware_version: str) -> List[CameraVulnerability]:
        """Get vulnerabilities for firmware version."""
        vulns = self.get_by_manufacturer(manufacturer)
        return [
            v for v in vulns
            if not v.firmware_versions_affected or firmware_version in v.firmware_versions_affected
        ]

    # ============================================================
    # Vulnerability Assessment
    # ============================================================

    async def check_camera_vulnerabilities(
        self,
        manufacturer: str,
        model: Optional[str] = None,
        firmware_version: Optional[str] = None,
        ip: Optional[str] = None,
        port: int = 80,
        run_exploits: bool = False,
    ) -> List[CameraVulnerability]:
        """
        Check camera for known vulnerabilities.
        
        Args:
            manufacturer: Camera manufacturer
            model: Camera model
            firmware_version: Firmware version
            ip: Camera IP (for active exploitation)
            port: Camera port
            run_exploits: Whether to attempt exploit verification
            
        Returns:
            List of matched vulnerabilities with status
        """
        # Find relevant CVEs
        vulns = self.get_by_manufacturer(manufacturer)
        
        if model:
            vulns = [v for v in vulns if not v.models_affected or model.lower() in [m.lower() for m in v.models_affected]]
        
        if firmware_version:
            vulns = [v for v in vulns if not v.firmware_versions_affected or firmware_version in v.firmware_versions_affected]
        
        results = []
        for vuln in vulns:
            # Run Nuclei template if available
            if vuln.nuclei_template and ip:
                await self._verify_with_nuclei(vuln, ip, port)
            
            # Run Metasploit module if available
            if vuln.metasploit_module and ip and run_exploits:
                await self._verify_with_metasploit(vuln, ip, port)
            
            results.append(vuln)
        
        return results

    async def _verify_with_nuclei(self, vuln: CameraVulnerability, ip: str, port: int) -> bool:
        """Verify vulnerability using Nuclei template."""
        if not vuln.nuclei_template:
            return False
        
        try:
            # Run specific template
            vulns = await self.nuclei.scan(
                targets=[f"{ip}:{port}"],
                template_dirs=[],
                extra_args=["-t", vuln.nuclei_template]
            )
            
            if vulns:
                vuln.status = VulnStatus.CONFIRMED_VULNERABLE
                vuln.verified_at = datetime.utcnow()
                vuln.proof["nuclei"] = [v.__dict__ for v in vulns]
                return True
        except Exception as e:
            logger.warning("Nuclei verification failed", cve=vuln.cve_id, error=str(e))
        
        return False

    async def _verify_with_metasploit(self, vuln: CameraVulnerability, ip: str, port: int) -> bool:
        """Verify vulnerability using Metasploit module."""
        if not vuln.metasploit_module:
            return False
        
        try:
            target = ExploitTarget(
                id=f"target_{ip}",
                target_type="host",
                address=ip,
                port=port,
                service="http",
            )
            
            result = await self.exploit_runner.execute(
                exploit_name=vuln.metasploit_module,
                target=target,
                source=ExploitSource.METASPLOIT_RPC,
            )
            
            if result.success:
                vuln.status = VulnStatus.EXPLOITED
                vuln.verified_at = datetime.utcnow()
                vuln.proof["metasploit"] = result.__dict__
                return True
            elif vuln.status == VulnStatus.UNKNOWN:
                vuln.status = VulnStatus.POTENTIALLY_VULNERABLE
        except Exception as e:
            logger.warning("Metasploit verification failed", cve=vuln.cve_id, error=str(e))
        
        return False

    # ============================================================
    # CVE Database Management
    # ============================================================

    def add_vulnerability(self, vuln: CameraVulnerability):
        """Add vulnerability to database."""
        self.cve_db.append(vuln)
        self._by_cve[vuln.cve_id.upper()] = vuln
        self._by_manufacturer.setdefault(vuln.manufacturer.lower(), []).append(vuln)

    def add_cve_from_dict(self, data: Dict[str, Any]):
        """Add vulnerability from dictionary."""
        vuln = CameraVulnerability(
            cve_id=data["cve_id"],
            name=data["name"],
            description=data["description"],
            manufacturer=data["manufacturer"],
            models_affected=data.get("models_affected", []),
            firmware_versions_affected=data.get("firmware_versions_affected", []),
            cvss_score=data.get("cvss_score"),
            severity=data.get("severity", "unknown"),
            exploit_available=data.get("exploit_available", False),
            exploit_path=data.get("exploit_path"),
            metasploit_module=data.get("metasploit_module"),
            nuclei_template=data.get("nuclei_template"),
            references=data.get("references", []),
            status=VulnStatus(data.get("status", "unknown")),
        )
        self.add_vulnerability(vuln)

    def search(self, query: str) -> List[CameraVulnerability]:
        """Search vulnerabilities by keyword."""
        query = query.lower()
        results = []
        for vuln in self.cve_db:
            if (query in vuln.cve_id.lower() or
                query in vuln.name.lower() or
                query in vuln.description.lower() or
                query in vuln.manufacturer.lower() or
                any(query in m.lower() for m in vuln.models_affected)):
                results.append(vuln)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics."""
        stats = {
            "total": len(self.cve_db),
            "by_severity": {},
            "by_manufacturer": {},
            "exploit_available": 0,
            "with_nuclei": 0,
            "with_metasploit": 0,
        }
        
        for vuln in self.cve_db:
            # By severity
            stats["by_severity"][vuln.severity] = stats["by_severity"].get(vuln.severity, 0) + 1
            
            # By manufacturer
            stats["by_manufacturer"][vuln.manufacturer] = stats["by_manufacturer"].get(vuln.manufacturer, 0) + 1
            
            # Capabilities
            if vuln.exploit_available:
                stats["exploit_available"] += 1
            if vuln.nuclei_template:
                stats["with_nuclei"] += 1
            if vuln.metasploit_module:
                stats["with_metasploit"] += 1
        
        return stats


# ============================================================
# Default CVE Database
# ============================================================

DEFAULT_CVE_DB = [
    # Hikvision
    CameraVulnerability(
        cve_id="CVE-2017-7921",
        name="Hikvision IP Camera Command Injection",
        description="Command injection in Hikvision IP cameras via /cgi-bin/hi3510/param.cgi",
        manufacturer="hikvision",
        models_affected=["DS-2CD*", "DS-2DE*", "DS-2DF*"],
        firmware_versions_affected=["<=5.4.5"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        metasploit_module="exploit/linux/http/hikvision_hi3510_cmd_injection",
        nuclei_template="cves/2017/CVE-2017-7921.yaml",
        references=[
            "https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
            "https://blog.rapid7.com/2017/08/18/cve-2017-7921/"
        ],
        status=VulnStatus.UNKNOWN,
    ),
    CameraVulnerability(
        cve_id="CVE-2021-36260",
        name="Hikvision Command Injection via Web Interface",
        description="Command injection in Hikvision web interface via /SDK/webLanguage",
        manufacturer="hikvision",
        models_affected=["DS-2CD*", "iDS-*"],
        firmware_versions_affected=["<=5.6.0"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        nuclei_template="cves/2021/CVE-2021-36260.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-36260"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Dahua
    CameraVulnerability(
        cve_id="CVE-2018-19061",
        name="Dahua Authentication Bypass",
        description="Authentication bypass in Dahua IP cameras via cookie manipulation",
        manufacturer="dahua",
        models_affected=["IPC-H*", "DH-IPC-*", "DH-SD*"],
        firmware_versions_affected=["<=4.500"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        metasploit_module="exploit/linux/http/dahua_auth_bypass",
        nuclei_template="cves/2018/CVE-2018-19061.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-19061"],
        status=VulnStatus.UNKNOWN,
    ),
    CameraVulnerability(
        cve_id="CVE-2021-33044",
        name="Dahua Arbitrary File Read",
        description="Arbitrary file read in Dahua cameras via /cgi-bin/downloadFile.cgi",
        manufacturer="dahua",
        models_affected=["IPC-H*", "DH-IPC-*"],
        firmware_versions_affected=["<=4.600"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        nuclei_template="cves/2021/CVE-2021-33044.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2021-33044"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Axis
    CameraVulnerability(
        cve_id="CVE-2019-2337",
        name="Axis Camera Admin Password Reset",
        description="Authentication bypass allowing admin password reset on Axis cameras",
        manufacturer="axis",
        models_affected=["Q60*", "P55*", "P56*"],
        firmware_versions_affected=["<=9.40.1"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        nuclei_template="cves/2019/CVE-2019-2337.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2019-2337"],
        status=VulnStatus.UNKNOWN,
    ),
    CameraVulnerability(
        cve_id="CVE-2022-34818",
        name="Axis Camera Command Injection",
        description="Command injection in Axis cameras via parameter injection",
        manufacturer="axis",
        models_affected=["P56*", "Q61*"],
        firmware_versions_affected=["<=10.12.100"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        nuclei_template="cves/2022/CVE-2022-34818.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2022-34818"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Foscam
    CameraVulnerability(
        cve_id="CVE-2017-8296",
        name="Foscam Camera Stack Overflow",
        description="Stack-based buffer overflow in Foscam cameras via CGI parameter",
        manufacturer="foscam",
        models_affected=["FI9821P", "FI9828P", "FI9928P"],
        firmware_versions_affected=["<=11.37.2.55"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        metasploit_module="exploit/linux/http/foscam_cgi_stack_overflow",
        nuclei_template="cves/2017/CVE-2017-8296.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-8296"],
        status=VulnStatus.UNKNOWN,
    ),
    CameraVulnerability(
        cve_id="CVE-2018-16882",
        name="Foscam Auth Bypass",
        description="Authentication bypass in Foscam cameras",
        manufacturer="foscam",
        models_affected=["FI9900P", "FI9928P"],
        firmware_versions_affected=["<=2.52.2.44"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        nuclei_template="cves/2018/CVE-2018-16882.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-16882"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Reolink
    CameraVulnerability(
        cve_id="CVE-2020-5854",
        name="Reolink Camera Command Injection",
        description="Command injection in Reolink cameras via /cgi-bin/api.cgi",
        manufacturer="reolink",
        models_affected=["RLC-*", "E1*", "C1*", "C2*"],
        firmware_versions_affected=["<=3.0.0.136_20031002"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        nuclei_template="cves/2020/CVE-2020-5854.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-5854"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # TP-Link Tapo
    CameraVulnerability(
        cve_id="CVE-2023-27159",
        name="TP-Link Tapo Command Injection",
        description="Command injection in TP-Link Tapo cameras via web interface",
        manufacturer="tp-link",
        models_affected=["C100", "C200", "C310"],
        firmware_versions_affected=["<=1.1.0"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        nuclei_template="cves/2023/CVE-2023-27159.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2023-27159"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Ubiquiti UniFi
    CameraVulnerability(
        cve_id="CVE-2020-8126",
        name="Ubiquiti UniFi Video Auth Bypass",
        description="Authentication bypass in Ubiquiti UniFi Video",
        manufacturer="ubiquiti",
        models_affected=["UVC-G3*", "UVC-G4*"],
        firmware_versions_affected=["<=3.10.13"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        metasploit_module="exploit/linux/http/ubiquiti_unifi_video_auth_bypass",
        nuclei_template="cves/2020/CVE-2020-8126.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2020-8126"],
        status=VulnStatus.UNKNOWN,
    ),
    
    # Generic / Multiple Vendors
    CameraVulnerability(
        cve_id="CVE-2017-7921",
        name="Multiple Vendor HiSilicon Chipset Command Injection",
        description="Command injection in HiSilicon-based IP cameras via /cgi-bin/hi3510/param.cgi",
        manufacturer="generic",
        models_affected=["hi3510", "hi3516", "hi3518", "hi3520", "hi3521"],
        firmware_versions_affected=["all"],
        cvss_score=9.8,
        severity="critical",
        exploit_available=True,
        metasploit_module="exploit/linux/http/hisilicon_cmd_injection",
        nuclei_template="cves/2017/CVE-2017-7921.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2017-7921"],
        status=VulnStatus.UNKNOWN,
    ),
    
    CameraVulnerability(
        cve_id="CVE-2018-12928",
        name="Multiple Vendor GoAhead Webserver Auth Bypass",
        description="Authentication bypass in GoAhead webserver used by many IP cameras",
        manufacturer="generic",
        models_affected=["goahead", "embedded"],
        firmware_versions_affected=["<=4.0.1"],
        cvss_score=7.5,
        severity="high",
        exploit_available=True,
        metasploit_module="exploit/linux/http/goahead_auth_bypass",
        nuclei_template="cves/2018/CVE-2018-12928.yaml",
        references=["https://nvd.nist.gov/vuln/detail/CVE-2018-12928"],
        status=VulnStatus.UNKNOWN,
    ),
]


async def check_camera_vulnerabilities(
    manufacturer: str,
    model: Optional[str] = None,
    firmware_version: Optional[str] = None,
    ip: Optional[str] = None,
    port: int = 80,
    run_exploits: bool = False,
) -> List[CameraVulnerability]:
    """Convenience function to check camera vulnerabilities."""
    checker = CameraVulnChecker()
    return await checker.check_camera_vulnerabilities(
        manufacturer=manufacturer,
        model=model,
        firmware_version=firmware_version,
        ip=ip,
        port=port,
        run_exploits=run_exploits,
    )


def load_cve_db(path: str) -> List[CameraVulnerability]:
    """Load CVE database from JSON file."""
    try:
        with open(path, 'r') as f:
            data = json.load(f)
        return [CameraVulnerability(**v) for v in data]
    except Exception as e:
        logger.error("Failed to load CVE database", path=path, error=str(e))
        return []


__all__ = [
    "VulnStatus",
    "CameraVulnerability",
    "CameraVulnChecker",
    "DEFAULT_CVE_DB",
    "check_camera_vulnerabilities",
    "load_cve_db",
]