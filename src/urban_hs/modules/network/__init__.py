"""
Network Module - Network scanning, vulnerability assessment, and device discovery.

Provides:
- Nmap wrapper for host discovery, port scanning, OS fingerprinting
- Nuclei runner for template-based vulnerability scanning
- SearchSploit integration for exploit database searches
- Router exploitation with RouterSploit and Hydra
"""

import asyncio
import ipaddress
import json
import os
import re
import socket
import structlog
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Set, Union
from enum import Enum
from urllib.parse import urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

logger = structlog.get_logger(__name__)


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
    protocol: str  # tcp/udp
    state: str  # open/closed/filtered
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
    status: str = "identified"  # identified, exploited, failed, patched
    exploited_at: Optional[datetime] = None
    proof: Dict[str, Any] = field(default_factory=dict)
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)


class NmapScanner:
    """
    Async Nmap wrapper for network scanning.
    
    Supports:
    - Host discovery (-sn)
    - Port scanning (-sS, -sT, -sU)
    - Service version detection (-sV)
    - OS fingerprinting (-O)
    - NSE script execution (--script)
    - XML/JSON output parsing
    """

    def __init__(
        self,
        nmap_path: str = "nmap",
        default_timing: str = "3",
        default_ports: str = "1-1000",
        default_scripts: List[str] = None,
    ):
        self.nmap_path = nmap_path
        self.default_timing = default_timing
        self.default_ports = default_ports
        self.default_scripts = default_scripts or ["vuln", "auth", "default"]

    async def scan(
        self,
        targets: Union[str, List[str]],
        scan_type: ScanType = ScanType.FULL_SCAN,
        ports: Optional[str] = None,
        timing: Optional[str] = None,
        scripts: Optional[List[str]] = None,
        extra_args: List[str] = None,
        timeout: int = 300,
    ) -> List[HostInfo]:
        """
        Execute nmap scan and return parsed HostInfo objects.
        """
        if isinstance(targets, str):
            targets = [targets]
        
        # Validate targets to prevent argument injection
        validated_targets = []
        for target in targets:
            try:
                # Validate as IP network (CIDR notation) or IP address
                ipaddress.ip_network(target, strict=False)
                validated_targets.append(target)
            except ValueError:
                try:
                    # Try as single IP address
                    ipaddress.ip_address(target)
                    validated_targets.append(target)
                except ValueError:
                    # Could also be a hostname - basic validation
                    if re.match(r'^[a-zA-Z0-9.-]+$', target):
                        validated_targets.append(target)
                    else:
                        logger.warning("Skipping invalid target", target=target)
        
        targets = validated_targets
        if not targets:
            logger.error("No valid targets provided")
            return []
        
        cmd = [self.nmap_path]
        
        # Timing template
        cmd.extend(["-T", timing or self.default_timing])
        
        # Output format
        cmd.extend(["-oX", "-"])  # XML to stdout
        
        # Scan type specific options
        # Check for root privileges for OS fingerprinting
        has_root = os.geteuid() == 0
        
        if scan_type == ScanType.HOST_DISCOVERY:
            cmd.append("-sn")
        elif scan_type == ScanType.PORT_SCAN:
            cmd.append("-sT")  # TCP connect scan (no root required)
            cmd.extend(["-p", ports or self.default_ports])
        elif scan_type == ScanType.SERVICE_VERSION:
            cmd.extend(["-sT", "-sV"])
            cmd.extend(["-p", ports or self.default_ports])
        elif scan_type == ScanType.OS_FINGERPRINT:
            cmd.extend(["-sT"])
            if has_root:
                cmd.extend(["-O"])
            else:
                logger.warning("OS fingerprinting (-O) requires root privileges, skipping")
            cmd.extend(["-p", ports or self.default_ports])
        elif scan_type == ScanType.VULN_SCAN:
            cmd.extend(["-sT", "-sV"])
            cmd.extend(["-p", ports or self.default_ports])
            cmd.extend(["--script", ",".join(self.default_scripts)])
        elif scan_type == ScanType.FULL_SCAN:
            cmd.extend(["-sT", "-sV"])
            if has_root:
                cmd.extend(["-O"])
            else:
                logger.warning("OS fingerprinting (-O) requires root privileges, skipping")
            cmd.extend(["-p", ports or self.default_ports])
            cmd.extend(["--script", ",".join(self.default_scripts)])
        
        # Custom scripts
        if scripts:
            cmd.extend(["--script", ",".join(scripts)])
        
        # Extra arguments
        if extra_args:
            cmd.extend(extra_args)
        
        # Targets
        cmd.extend(targets)

        logger.info("Starting nmap scan", cmd=" ".join(cmd), targets=targets, scan_type=scan_type.value)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode != 0 and proc.returncode != 1:  # 1 = hosts down
                stderr_str = stderr.decode() if stderr else ""
                logger.error("Nmap scan failed", returncode=proc.returncode, stderr=stderr_str[:500])
                return []

            return self._parse_xml_output(stdout.decode())

        except asyncio.TimeoutError:
            logger.error("Nmap scan timeout", timeout=timeout)
            return []
        except Exception as e:
            logger.error("Nmap scan error", error=str(e))
            return []

    def _parse_xml_output(self, xml_str: str) -> List[HostInfo]:
        """Parse nmap XML output into HostInfo objects."""
        hosts = []
        try:
            root = ET.fromstring(xml_str)
        except ET.ParseError as e:
            logger.error("Failed to parse nmap XML", error=str(e))
            return []

        for host_elem in root.findall("host"):
            try:
                host = self._parse_host_element(host_elem)
                if host:
                    hosts.append(host)
            except Exception as e:
                logger.warning("Failed to parse host element", error=str(e))

        return hosts

    def _parse_host_element(self, host_elem: ET.Element) -> Optional[HostInfo]:
        """Parse individual host XML element."""
        # Host state
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            return None

        # Address
        ip = None
        mac = None
        vendor = None
        for addr in host_elem.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
            elif addr.get("addrtype") == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")

        if not ip:
            return None

        # Hostname
        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    hostname = hn.get("name")
                    break

        # OS fingerprint
        os_guess = None
        os_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_guess = osmatch.get("name")
                os_accuracy = int(osmatch.get("accuracy", 0))
                break

        # Ports
        ports = []
        ports_elem = host_elem.find("ports")
        if ports_elem is not None:
            for port_elem in ports_elem.findall("port"):
                port_info = self._parse_port_element(port_elem)
                if port_info:
                    ports.append(port_info)

        return HostInfo(
            ip=ip,
            hostname=hostname,
            mac=mac,
            vendor=vendor,
            os_guess=os_guess,
            os_accuracy=os_accuracy,
            state="up",
            ports=ports,
        )

    def _parse_port_element(self, port_elem: ET.Element) -> Optional[PortInfo]:
        """Parse individual port element."""
        try:
            port = int(port_elem.get("portid", 0))
            protocol = port_elem.get("protocol", "tcp")
            
            state_elem = port_elem.find("state")
            state = state_elem.get("state", "unknown") if state_elem is not None else "unknown"
            
            if state != "open":
                return PortInfo(port=port, protocol=protocol, state=state)

            service_elem = port_elem.find("service")
            service = None
            version = None
            product = None
            extrainfo = None
            
            if service_elem is not None:
                service = service_elem.get("name")
                version = service_elem.get("version")
                product = service_elem.get("product")
                extrainfo = service_elem.get("extrainfo")

            scripts = []
            for script_elem in port_elem.findall("script"):
                scripts.append({
                    "id": script_elem.get("id"),
                    "output": script_elem.get("output"),
                })

            return PortInfo(
                port=port,
                protocol=protocol,
                state=state,
                service=service,
                version=version,
                product=product,
                extrainfo=extrainfo,
                scripts=scripts,
            )
        except Exception as e:
            logger.warning("Failed to parse port", error=str(e))
            return None


class NucleiRunner:
    """
    Nuclei vulnerability scanner wrapper.
    
    Runs nuclei templates and parses JSONL output.
    Supports template filtering by tags, severity, author, etc.
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_dir: Optional[str] = None,
        severity_levels: List[str] = None,
        tags: List[str] = None,
        rate_limit: int = 150,
        timeout: int = 300,
    ):
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir
        self.severity_levels = severity_levels or ["critical", "high", "medium", "low"]
        self.tags = tags or []
        self.rate_limit = rate_limit
        self.timeout = timeout

    async def scan(
        self,
        targets: Union[str, List[str]],
        template_dirs: List[str] = None,
        exclude_tags: List[str] = None,
        extra_args: List[str] = None,
    ) -> List[Vulnerability]:
        """Execute nuclei scan and return vulnerabilities."""
        if isinstance(targets, str):
            targets = [targets]

        cmd = [self.nuclei_path]
        
        # Targets
        cmd.extend(["-target", ",".join(targets)])
        
        # Template directories
        if template_dirs:
            for d in template_dirs:
                cmd.extend(["-t", d])
        
        # Severity filter
        if self.severity_levels:
            cmd.extend(["-severity", ",".join(self.severity_levels)])
        
        # Tags
        if self.tags:
            cmd.extend(["-tags", ",".join(self.tags)])
        if exclude_tags:
            for tag in exclude_tags:
                cmd.extend(["-exclude-tags", tag])
        
        # Rate limiting
        cmd.extend(["-rate-limit", str(self.rate_limit)])
        
        # Output format
        cmd.extend(["-jsonl", "-"])
        
        # Extra args
        if extra_args:
            cmd.extend(extra_args)

        logger.info("Starting nuclei scan", cmd=" ".join(cmd), targets=targets)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            vulnerabilities = []
            
            # Read JSONL output line by line
            async for line in proc.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                try:
                    vuln_data = json.loads(line)
                    vuln = self._parse_nuclei_finding(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            await asyncio.wait_for(proc.wait(), timeout=300)

            logger.info("Nuclei scan completed", vulns_found=len(vulnerabilities))
            return vulnerabilities

        except asyncio.TimeoutError:
            logger.error("Nuclei scan timeout")
            return []
        except Exception as e:
            logger.error("Nuclei scan error", error=str(e))
            return []

    def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Optional[Vulnerability]:
        """Parse nuclei JSONL finding into Vulnerability object."""
        try:
            info = data.get("info", {})
            severity_str = info.get("severity", "unknown").lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }
            
            # Extract CVSS if available
            cvss = None
            cvss_str = info.get("classification", {}).get("cvss-metrics", "")
            if cvss_str:
                try:
                    cvss = float(cvss_str.split("/")[-1])
                except (ValueError, IndexError):
                    pass

            return Vulnerability(
                id=data.get("template-id", data.get("template", "")),
                cve_id=info.get("cve", [None])[0] if info.get("cve") else None,
                name=info.get("name", ""),
                severity=severity_map.get(severity_str, Severity.UNKNOWN),
                cvss_score=cvss,
                description=info.get("description", ""),
                target_ip=self._extract_target_ip(data.get("matched-at", "")),
                exploit_available=info.get("exploit", False),
                nuclei_template=data.get("template-id", data.get("template", "")),
                status="identified",
                references=info.get("reference", []),
                tags=info.get("tags", []),
            )
        except Exception as e:
            logger.warning("Failed to parse nuclei finding", error=str(e))
            return None

    def _extract_target_ip(self, matched_at: str) -> str:
        """Extract target IP from matched-at string."""
        # Format: "http://192.168.1.1:80/path"
        try:
            from urllib.parse import urlparse
            parsed = urlparse(matched_at)
            return parsed.hostname or ""
        except Exception:
            return ""


class SearchSploitIntegration:
    """
    Local ExploitDB search integration using searchsploit.
    """

    def __init__(self, searchsploit_path: str = "searchsploit"):
        self.searchsploit_path = searchsploit_path

    async def search(self, query: str, exact: bool = False, json_output: bool = True) -> List[Dict[str, Any]]:
        """Search ExploitDB for exploits matching query."""
        cmd = [self.searchsploit_path]
        
        if json_output:
            cmd.append("-j")
        if exact:
            cmd.append("-e")
        
        cmd.append(query)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)

            if proc.returncode != 0:
                logger.warning("searchsploit failed", stderr=stderr.decode()[:200])
                return []

            if json_output:
                try:
                    data = json.loads(stdout.decode())
                    return data.get("RESULTS_EXPLOIT", [])
                except json.JSONDecodeError:
                    logger.warning("Failed to parse searchsploit JSON output")
                    return []

        except Exception as e:
            logger.error("searchsploit error", error=str(e))
            return []

        return []

    async def get_exploit(self, exploit_id: str, output_dir: str) -> Optional[str]:
        """Download exploit by ID to output directory."""
        # Validate exploit_id - ExploitDB IDs are integers
        if not re.match(r'^\d+$', exploit_id):
            logger.error("Invalid exploit_id format", exploit_id=exploit_id)
            return None
        
        try:
            cmd = [self.searchsploit_path, "-m", exploit_id, "-p", output_dir]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                # Find the downloaded file
                output = stdout.decode()
                for line in output.split("\n"):
                    if "Copied" in line or "saved" in line:
                        # Extract path
                        parts = line.split()
                        for part in parts:
                            if part.endswith((".py", ".c", ".rb", ".pl", ".sh", ".txt", ".html")):
                                return part
            return None
        except Exception as e:
            logger.error("Failed to download exploit", error=str(e))
            return None


class RouterScanner:
    """
    Router vulnerability scanner using RouterSploit and Hydra.
    """

    def __init__(
        self,
        routersploit_path: str = "routersploit",
        hydra_path: str = "hydra",
    ):
        self.routersploit_path = routersploit_path
        self.hydra_path = hydra_path

    async def scan_router(
        self,
        target_ip: str,
        ports: List[int] = None,
        modules: List[str] = None,
    ) -> List[Dict[str, Any]]:
        """Run RouterSploit against target."""
        # This would run routersploit modules
        # Implementation depends on routersploit's Python API or CLI
        return []

    async def brute_force_credentials(
        self,
        target_ip: str,
        service: str,  # ssh, http, ftp, telnet, etc.
        username_list: List[str],
        password_list: List[str],
        port: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Run Hydra credential brute force."""
        port = port or self._default_port(service)
        
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as uf:
            uf.write("\n".join(username_list))
            user_file = uf.name
        
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as pf:
            pf.write("\n".join(password_list))
            pass_file = pf.name

        try:
            cmd = [
                self.hydra_path,
                "-L", user_file,
                "-P", pass_file,
                "-t", "4",
                "-f",  # Exit on first success
                "-v",
                f"{service}://{target_ip}:{port}",
            ]
            
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)
            
            results = []
            stdout_str = stdout.decode()
            
            # Parse hydra output for successful logins using regex
            # Output format: [22][ssh] host: 192.168.1.1   login: admin   password: 12345
            import re
            for line in stdout_str.split("\n"):
                match = re.search(r"login:\s+(\S+)\s+password:\s+(\S+)", line)
                if match:
                    username, password = match.group(1), match.group(2)
                    results.append({
                        "service": service,
                        "ip": target_ip,
                        "port": port,
                        "username": username,
                        "password": password,
                    })
            
            return results
            
        finally:
            os.unlink(user_file)
            os.unlink(pass_file)

    def _default_port(self, service: str) -> int:
        ports = {
            "ssh": 22,
            "http": 80,
            "https": 443,
            "ftp": 21,
            "telnet": 23,
            "smtp": 25,
            "smb": 445,
            "rdp": 3389,
            "mysql": 3306,
            "postgres": 5432,
        }
        return ports.get(service, 80)


class CameraDiscovery:
    """
    Discovers and enumerates IP cameras via multiple protocols.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.default_creds = [
            ("admin", "admin"),
            ("admin", "12345"),
            ("admin", "123456"),
            ("admin", ""),
            ("admin", "password"),
            ("root", "root"),
            ("root", "admin"),
            ("root", "12345"),
            ("admin", "1234"),
            ("ubnt", "ubnt"),
            ("admin", "888888"),
        ]

    async def discover_cameras(self, network: str = "192.168.1.0/24") -> List[Dict[str, Any]]:
        """Discover cameras via multiple methods."""
        cameras = []
        
        # 1. mDNS/Bonjour discovery
        mdns_cameras = await self._mdns_discovery()
        cameras.extend(mdns_cameras)
        
        # 2. UPnP/SSDP discovery
        upnp_cameras = await self._upnp_discovery()
        cameras.extend(upnp_cameras)
        
        # 3. ONVIF WS-Discovery
        onvif_cameras = await self._onvif_discovery()
        cameras.extend(onvif_cameras)
        
        # 4. RTSP port scan
        rtsp_cameras = await self._rtsp_scan(network)
        cameras.extend(rtsp_cameras)
        
        # 5. HTTP fingerprinting
        http_cameras = await self._http_fingerprint(network)
        cameras.extend(http_cameras)
        
        # Deduplicate by IP/MAC
        seen = set()
        unique = []
        for cam in cameras:
            key = cam.get("ip") or cam.get("mac")
            if key and key not in seen:
                seen.add(key)
                unique.append(cam)
        
        return unique

    async def _mdns_discovery(self) -> List[Dict[str, Any]]:
        """Discover cameras via mDNS/Bonjour."""
        cameras = []
        try:
            # Use avahi-browse or dns-sd
            proc = await asyncio.create_subprocess_exec(
                "avahi-browse", "-t", "_rtsp._tcp", "-t", "_onvif._tcp", "-r", "-p",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
            
            # Parse avahi output (uses ; as delimiter from -p flag)
            for line in stdout.decode().split("\n"):
                if "IPv4" in line or "IPv6" in line:
                    # Parse avahi-browse -p output format:
                    # =;interface;IPv4/IPv6;name;type;domain;hostname;IP;port;...
                    parts = line.split(";")
                    if len(parts) >= 8:
                        cameras.append({
                            "discovery_method": "mdns",
                            "hostname": parts[6],   # hostname
                            "ip": parts[7],         # IP address
                            "port": int(parts[8]) if parts[8].isdigit() else None,
                            "service": parts[4],    # service type (e.g., _rtsp._tcp)
                            "interface": parts[1],
                        })
        except Exception as e:
            logger.warning("mDNS discovery failed", error=str(e))
        
        return cameras

    async def _upnp_discovery(self) -> List[Dict[str, Any]]:
        """Discover devices via UPnP/SSDP."""
        cameras = []
        try:
            # SSDP M-SEARCH
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                "MAN: \"ssdp:discover\"\r\n"
                "MX: 3\r\n"
                "ST: urn:schemas-upnp-org:device:Basic:1\r\n"
                "\r\n"
            )
            
            def _recv_responses():
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                sock.settimeout(5)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.sendto(ssdp_request.encode(), ("239.255.255.250", 1900))
                
                responses = []
                try:
                    while True:
                        data, addr = sock.recvfrom(65535)
                        responses.append((data, addr))
                except socket.timeout:
                    pass
                finally:
                    sock.close()
                return responses
            
            # Run blocking socket I/O in thread pool to not block event loop
            responses = await asyncio.to_thread(_recv_responses)
            
            for data, addr in responses:
                response = data.decode()
                if "camera" in response.lower() or "onvif" in response.lower() or "rtsp" in response.lower():
                    cameras.append({
                        "discovery_method": "upnp",
                        "ip": addr[0],
                        "response": response[:500],
                    })
                
        except Exception as e:
            logger.warning("UPnP discovery failed", error=str(e))
        
        return cameras

    async def _onvif_discovery(self) -> List[Dict[str, Any]]:
        """Discover ONVIF cameras via WS-Discovery."""
        cameras = []
        try:
            # WS-Discovery SOAP request
            ws_discovery = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" '
                'xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
                'xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
                '<soap:Header>'
                '<wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>'
                '<wsa:MessageID>uuid:12345678-1234-1111-2222-333344445555</wsa:MessageID>'
                '<wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>'
                '</soap:Header>'
                '<soap:Body>'
                '<wsd:Probe/>'
                '</soap:Body>'
                '</soap:Envelope>'
            )
            
            # Send to multicast address
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(ws_discovery.encode(), ("239.255.255.250", 3702))
            
            async def recv_responses():
                responses = []
                try:
                    while True:
                        # Use asyncio.to_thread to avoid blocking event loop
                        data, addr = await asyncio.to_thread(sock.recvfrom, 65535)
                        response = data.decode()
                        # Parse SOAP response for ONVIF device info
                        if "onvif" in response.lower() or "device" in response.lower():
                            import re
                            # Extract XAddrs for device service
                            xaddrs_match = re.search(r'<d:XAddrs>([^<]+)</d:XAddrs>', response)
                            types_match = re.search(r'<d:Types>([^<]+)</d:Types>', response)
                            cameras.append({
                                "discovery_method": "onvif_ws_discovery",
                                "ip": addr[0],
                                "xaddrs": xaddrs_match.group(1) if xaddrs_match else None,
                                "types": types_match.group(1) if types_match else None,
                            })
                except socket.timeout:
                    pass
                finally:
                    sock.close()
                return cameras
            
            await recv_responses()
            
        except Exception as e:
            logger.warning("ONVIF discovery failed", error=str(e))
        return cameras

    async def _rtsp_scan(self, network: str) -> List[Dict[str, Any]]:
        """Scan for open RTSP ports (554, 8554)."""
        cameras = []
        try:
            # Use nmap for RTSP port scan
            nmap = NmapScanner()
            hosts = await nmap.scan(
                targets=network,
                scan_type=ScanType.PORT_SCAN,
                ports="554,8554",
            )
            
            for host in hosts:
                for port in host.ports:
                    if port.port in (554, 8554) and port.state == "open":
                        # Try RTSP DESCRIBE
                        rtsp_info = await self._rtsp_describe(host.ip, port.port)
                        cameras.append({
                            "ip": host.ip,
                            "port": port.port,
                            "protocol": "rtsp",
                            "rtsp_info": rtsp_info,
                        })
        except Exception as e:
            logger.warning("RTSP scan failed", error=str(e))
        return cameras

    async def _rtsp_describe(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Send RTSP DESCRIBE request to get stream info."""
        try:
            url = f"rtsp://{ip}:{port}/"
            # This would use an RTSP client
            return {"url": url}
        except Exception:
            return None

    async def _http_fingerprint(self, network: str) -> List[Dict[str, Any]]:
        """Fingerprint cameras via HTTP."""
        if not AIOHTTP_AVAILABLE:
            logger.warning("HTTP fingerprinting requires aiohttp package, skipping")
            return []
        
        cameras = []
        try:
            # Use nmap to find HTTP services on common camera ports
            nmap = NmapScanner()
            hosts = await nmap.scan(
                targets=network,
                scan_type=ScanType.PORT_SCAN,
                ports="80,8080,8081,8443,8888,8889,5000,5001",
            )
            
            import aiohttp
            import asyncio
            
            # Common camera paths to check
            camera_paths = [
                "/", "/index.html", "/video", "/stream", "/live",
                "/cgi-bin/nph-zms", "/cgi-bin/cgi?action=snapshot",
                "/snapshot.cgi", "/image.jpg", "/mjpeg.cgi",
                "/onvif/device_service", "/api/camera", "/web/",
                "/web/cgi-bin/hi3510/param.cgi", "/cgi-bin/main.cgi",
                "/ISAPI/Streaming/channels/101/picture", "/onvif/Device"
            ]
            
            async def check_http_camera(host_ip: str, port: int) -> Optional[Dict[str, Any]]:
                try:
                    async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
                        for path in camera_paths:
                            try:
                                url = f"http://{host_ip}:{port}{path}"
                                async with session.get(url) as resp:
                                    if resp.status == 200:
                                        content = await resp.text()
                                        # Check for camera indicators
                                        camera_indicators = [
                                            "camera", "ipcam", "webcam", "dvrt", "nvr",
                                            "hikvision", "dahua", "axis", "foscam", "amcrest",
                                            "reolink", "tplink", "ubiquiti", "unifi",
                                            "onvif", "rtsp", "mjpeg", "h264", "h265"
                                        ]
                                        if any(ind in content.lower() for ind in camera_indicators):
                                            return {
                                                "ip": host_ip,
                                                "port": port,
                                                "protocol": "http",
                                                "path": path,
                                                "server": resp.headers.get("Server", ""),
                                                "title": self._extract_title(content),
                                            }
                            except Exception:
                                continue
                except Exception:
                    pass
                return None
            
            # Run checks in parallel
            tasks = []
            for host in hosts:
                for port_info in host.ports:
                    if port_info.port in (80, 8080, 8081, 8443, 8888, 8889, 5000, 5001) and port_info.state == "open":
                        tasks.append(check_http_camera(host.ip, port_info.port))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if result and not isinstance(result, Exception):
                    cameras.append(result)
                    
        except Exception as e:
            logger.warning("HTTP fingerprinting failed", error=str(e))
        return cameras
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML content."""
        import re
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""


class NetworkModule:
    """Main network module integrating all scanning capabilities."""

    def __init__(
        self,
        nmap_path: str = "nmap",
        nuclei_path: str = "nuclei",
        searchsploit_path: str = "searchsploit",
        routersploit_path: str = "routersploit",
        hydra_path: str = "hydra",
    ):
        self.nmap = NmapScanner(nmap_path=nmap_path)
        self.nuclei = NucleiRunner(nuclei_path=nuclei_path)
        self.searchsploit = SearchSploitIntegration(searchsploit_path=searchsploit_path)
        self.router_scanner = RouterScanner(
            routersploit_path=routersploit_path,
            hydra_path=hydra_path,
        )
        self.camera_discovery = CameraDiscovery()

    async def full_network_assessment(
        self,
        network: str = "192.168.1.0/24",
        scan_type: ScanType = ScanType.FULL_SCAN,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """Run complete network assessment."""
        results = {
            "hosts": [],
            "vulnerabilities": [],
            "cameras": [],
            "routers": [],
            "credentials": [],
            "summary": {},
        }

        # 1. Host discovery and port scanning
        if progress_callback:
            progress_callback("Starting host discovery and port scanning...")
        hosts = await self.nmap.scan(network, ScanType.FULL_SCAN)
        results["hosts"] = [h.__dict__ for h in hosts]

        # 2. Nuclei vulnerability scan
        if progress_callback:
            progress_callback("Running Nuclei vulnerability scan...")
        vulns = await self.nuclei.scan([h.ip for h in hosts])
        results["vulnerabilities"] = [v.__dict__ for v in vulns]

        # 3. Camera discovery
        if progress_callback:
            progress_callback("Discovering cameras...")
        cameras = await self.camera_discovery.discover_cameras()
        results["cameras"] = cameras

        # Convert vulnerabilities to dict with string severity for JSON serialization
        vuln_dicts = []
        for v in vulns:
            vuln_dict = v.__dict__.copy()
            vuln_dict["severity"] = v.severity.value  # Convert Enum to string
            vuln_dicts.append(vuln_dict)
        
        # 4. Router scanning (if any routers detected)
        router_ips = [h.ip for h in hosts if any(p.port in [80, 443, 8080, 8443] for p in h.ports)]
        for ip in router_ips:
            if progress_callback:
                progress_callback(f"Scanning router {ip}...")
            # router_results = await self.router_scanner.scan_router(ip)
            # results["routers"].extend(router_results)

        # Summary
        results["summary"] = {
            "total_hosts": len(hosts),
            "total_ports_open": sum(len(h.ports) for h in hosts),
            "vulnerabilities_found": len(vuln_dicts),
            "cameras_found": len(results["cameras"]),
            "critical_vulns": len([v for v in vuln_dicts if v.get("severity") == "critical"]),
            "high_vulns": len([v for v in vuln_dicts if v.get("severity") == "high"]),
        }
        
        results["vulnerabilities"] = vuln_dicts


# Exports
__all__ = [
    "ScanType",
    "Severity",
    "PortInfo",
    "HostInfo",
    "Vulnerability",
    "NmapScanner",
    "NucleiRunner",
    "SearchSploitIntegration",
    "RouterScanner",
    "CameraDiscovery",
    "NetworkModule",
]