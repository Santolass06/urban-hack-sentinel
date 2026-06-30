"""
IP camera discovery and enumeration.
"""

import asyncio
import re
import socket
from typing import Any, Dict, List, Optional

import structlog

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

from urban_hs.modules.network.scanner import NmapScanner
from urban_hs.modules.network.types import ScanType

logger = structlog.get_logger(__name__)


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
        cameras = []

        mdns_cameras = await self._mdns_discovery()
        cameras.extend(mdns_cameras)

        upnp_cameras = await self._upnp_discovery()
        cameras.extend(upnp_cameras)

        onvif_cameras = await self._onvif_discovery()
        cameras.extend(onvif_cameras)

        rtsp_cameras = await self._rtsp_scan(network)
        cameras.extend(rtsp_cameras)

        http_cameras = await self._http_fingerprint(network)
        cameras.extend(http_cameras)

        seen = set()
        unique = []
        for cam in cameras:
            key = cam.get("ip") or cam.get("mac")
            if key and key not in seen:
                seen.add(key)
                unique.append(cam)

        return unique

    async def _mdns_discovery(self) -> List[Dict[str, Any]]:
        cameras = []
        try:
            proc = await asyncio.create_subprocess_exec(
                "avahi-browse", "-t", "_rtsp._tcp", "-t", "_onvif._tcp", "-r", "-p",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)

            for line in stdout.decode().split("\n"):
                if "IPv4" in line or "IPv6" in line:
                    parts = line.split(";")
                    if len(parts) >= 8:
                        cameras.append({
                            "discovery_method": "mdns",
                            "hostname": parts[6],
                            "ip": parts[7],
                            "port": int(parts[8]) if parts[8].isdigit() else None,
                            "service": parts[4],
                            "interface": parts[1],
                        })
        except Exception as e:
            logger.warning("mDNS discovery failed", error=str(e))

        return cameras

    async def _upnp_discovery(self) -> List[Dict[str, Any]]:
        cameras = []
        try:
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
        cameras = []
        try:
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

            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.settimeout(5)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(ws_discovery.encode(), ("239.255.255.250", 3702))

            async def recv_responses():
                responses = []
                try:
                    while True:
                        data, addr = await asyncio.to_thread(sock.recvfrom, 65535)
                        response = data.decode()
                        if "onvif" in response.lower() or "device" in response.lower():
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
        cameras = []
        try:
            nmap = NmapScanner()
            hosts = await nmap.scan(
                targets=network,
                scan_type=ScanType.PORT_SCAN,
                ports="554,8554",
            )

            for host in hosts:
                for port in host.ports:
                    if port.port in (554, 8554) and port.state == "open":
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
        try:
            url = f"rtsp://{ip}:{port}/"
            return {"url": url}
        except Exception:
            return None

    async def _http_fingerprint(self, network: str) -> List[Dict[str, Any]]:
        if not AIOHTTP_AVAILABLE:
            logger.warning("HTTP fingerprinting requires aiohttp package, skipping")
            return []

        cameras = []
        try:
            nmap = NmapScanner()
            hosts = await nmap.scan(
                targets=network,
                scan_type=ScanType.PORT_SCAN,
                ports="80,8080,8081,8443,8888,8889,5000,5001",
            )

            import aiohttp

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
        match = re.search(r'<title[^>]*>([^<]+)</title>', html, re.IGNORECASE)
        return match.group(1).strip() if match else ""
