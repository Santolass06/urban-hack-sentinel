"""
Network module shared types.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ScanType(Enum):
    HOST_DISCOVERY = "host_discovery"
    PORT_SCAN = "port_scan"
    SERVICE_VERSION = "service_version"
    OS_FINGERPRINT = "os_fingerprint"
    VULN_SCAN = "vuln_scan"
    FULL_SCAN = "full_scan"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class PortInfo:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None
    product: Optional[str] = None
    extrainfo: Optional[str] = None
    scripts: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class HostInfo:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os_guess: Optional[str] = None
    os_accuracy: Optional[int] = None
    state: str = "up"
    ports: List[PortInfo] = field(default_factory=list)
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    id: str
    cve_id: Optional[str] = None
    name: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: Optional[float] = None
    description: str = ""
    target_ip: str = ""
    target_port: Optional[int] = None
    exploit_available: bool = False
    exploit_path: Optional[str] = None
    metasploit_module: Optional[str] = None
    nuclei_template: Optional[str] = None
    status: str = "identified"
    exploited_at: Optional[datetime] = None
    proof: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
