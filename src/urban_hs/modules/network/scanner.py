"""
Nmap scanner wrapper.
"""

import asyncio
import ipaddress
import os
import re
import structlog
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Union

from urban_hs.modules.network.types import HostInfo, PortInfo, ScanType

logger = structlog.get_logger(__name__)


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
        if isinstance(targets, str):
            targets = [targets]

        validated_targets = []
        for target in targets:
            try:
                ipaddress.ip_network(target, strict=False)
                validated_targets.append(target)
            except ValueError:
                try:
                    ipaddress.ip_address(target)
                    validated_targets.append(target)
                except ValueError:
                    if re.match(r'^[a-zA-Z0-9.-]+$', target):
                        validated_targets.append(target)
                    else:
                        logger.warning("Skipping invalid target", target=target)

        targets = validated_targets
        if not targets:
            logger.error("No valid targets provided")
            return []

        cmd = [self.nmap_path]
        cmd.extend(["-T", timing or self.default_timing])
        cmd.extend(["-oX", "-"])

        has_root = os.geteuid() == 0

        if scan_type == ScanType.HOST_DISCOVERY:
            cmd.append("-sn")
        elif scan_type == ScanType.PORT_SCAN:
            cmd.append("-sT")
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

        if scripts:
            cmd.extend(["--script", ",".join(scripts)])

        if extra_args:
            cmd.extend(extra_args)

        cmd.extend(targets)

        logger.info("Starting nmap scan", cmd=" ".join(cmd), targets=targets, scan_type=scan_type.value)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            if proc.returncode != 0 and proc.returncode != 1:
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
        status = host_elem.find("status")
        if status is None or status.get("state") != "up":
            return None

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

        hostname = None
        hostnames_elem = host_elem.find("hostnames")
        if hostnames_elem is not None:
            for hn in hostnames_elem.findall("hostname"):
                if hn.get("type") in ("PTR", "user"):
                    hostname = hn.get("name")
                    break

        os_guess = None
        os_accuracy = None
        os_elem = host_elem.find("os")
        if os_elem is not None:
            for osmatch in os_elem.findall("osmatch"):
                os_guess = osmatch.get("name")
                os_accuracy = int(osmatch.get("accuracy", 0))
                break

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
