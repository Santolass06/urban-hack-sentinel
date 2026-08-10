"""
Network module shared types.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


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
    service: str | None = None
    version: str | None = None
    product: str | None = None
    extrainfo: str | None = None
    scripts: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class HostInfo:
    ip: str
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    os_guess: str | None = None
    os_accuracy: int | None = None
    state: str = "up"
    ports: list[PortInfo] = field(default_factory=list)
    vulns: list[dict[str, Any]] = field(default_factory=list)
    last_seen: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Vulnerability:
    id: str
    cve_id: str | None = None
    name: str = ""
    severity: Severity = Severity.UNKNOWN
    cvss_score: float | None = None
    description: str = ""
    target_ip: str = ""
    target_port: int | None = None
    exploit_available: bool = False
    exploit_path: str | None = None
    metasploit_module: str | None = None
    nuclei_template: str | None = None
    status: str = "identified"
    exploited_at: datetime | None = None
    proof: dict[str, Any] = field(default_factory=dict)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
