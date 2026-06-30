"""
Network Module - Network scanning, vulnerability assessment, and device discovery.

Re-exports all classes for backward compatibility.
"""

from typing import Any, Callable, Dict, List, Optional

from urban_hs.modules.network.camera import CameraDiscovery
from urban_hs.modules.network.nuclei import NucleiRunner
from urban_hs.modules.network.router import RouterScanner
from urban_hs.modules.network.scanner import NmapScanner
from urban_hs.modules.network.searchsploit import SearchSploitIntegration
from urban_hs.modules.network.types import (
    HostInfo,
    PortInfo,
    ScanType,
    Severity,
    Vulnerability,
)


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
        results = {
            "hosts": [],
            "vulnerabilities": [],
            "cameras": [],
            "routers": [],
            "credentials": [],
            "summary": {},
        }

        if progress_callback:
            progress_callback("Starting host discovery and port scanning...")
        hosts = await self.nmap.scan(network, ScanType.FULL_SCAN)
        results["hosts"] = [h.__dict__ for h in hosts]

        if progress_callback:
            progress_callback("Running Nuclei vulnerability scan...")
        vulns = await self.nuclei.scan([h.ip for h in hosts])

        vuln_dicts = []
        for v in vulns:
            vuln_dict = v.__dict__.copy()
            vuln_dict["severity"] = v.severity.value
            vuln_dicts.append(vuln_dict)

        if progress_callback:
            progress_callback("Discovering cameras...")
        cameras = await self.camera_discovery.discover_cameras()
        results["cameras"] = cameras

        router_ips = [h.ip for h in hosts if any(p.port in [80, 443, 8080, 8443] for p in h.ports)]
        for ip in router_ips:
            if progress_callback:
                progress_callback(f"Scanning router {ip}...")

        results["summary"] = {
            "total_hosts": len(hosts),
            "total_ports_open": sum(len(h.ports) for h in hosts),
            "vulnerabilities_found": len(vuln_dicts),
            "cameras_found": len(results["cameras"]),
            "critical_vulns": len([v for v in vuln_dicts if v.get("severity") == "critical"]),
            "high_vulns": len([v for v in vuln_dicts if v.get("severity") == "high"]),
        }

        results["vulnerabilities"] = vuln_dicts

        return results


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
