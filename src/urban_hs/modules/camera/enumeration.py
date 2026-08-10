"""
Camera Enumeration Module - Deep camera enumeration and credential testing.

Provides:
- Authentication testing (Basic/Digest/NTLM)
- Default credential testing
- Configuration dump extraction
- Firmware version extraction
- ONVIF device information
- RTSP stream discovery
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any
from urllib.parse import urlparse

import structlog

# Optional imports with graceful fallback
try:
    import aiohttp

    AIOHTTP_AVAILABLE = True
except ImportError:
    aiohttp = None
    AIOHTTP_AVAILABLE = False

try:
    import onvif

    ONVIF_AVAILABLE = True
except ImportError:
    onvif = None
    ONVIF_AVAILABLE = False

logger = structlog.get_logger(__name__)


class AuthType(Enum):
    """Authentication types."""

    NONE = "none"
    BASIC = "basic"
    DIGEST = "digest"
    NTLM = "ntlm"
    FORM = "form"
    BEARER = "bearer"


class CameraProtocol(Enum):
    """Camera protocols."""

    HTTP = "http"
    HTTPS = "https"
    RTSP = "rtsp"
    ONVIF = "onvif"


@dataclass
class CameraCredential:
    """Camera credential information."""

    username: str
    password: str
    auth_type: AuthType = AuthType.BASIC
    source: str = "default"  # default, brute_force, config_dump, default_db
    verified: bool = False
    verified_at: datetime | None = None
    realm: str | None = None


@dataclass
class CameraConfig:
    """Camera configuration dump."""

    manufacturer: str | None = None
    model: str | None = None
    firmware_version: str | None = None
    serial_number: str | None = None
    mac_address: str | None = None
    ip_address: str | None = None
    network_config: dict[str, Any] = field(default_factory=dict)
    wifi_config: dict[str, Any] = field(default_factory=dict)
    rtsp_streams: list[dict[str, Any]] = field(default_factory=list)
    onvif_profiles: list[dict[str, Any]] = field(default_factory=list)
    users: list[dict[str, Any]] = field(default_factory=list)
    motion_regions: list[dict[str, Any]] = field(default_factory=list)
    ptz_config: dict[str, Any] = field(default_factory=dict)
    raw_config: dict[str, Any] = field(default_factory=dict)


@dataclass
class CameraFirmware:
    """Camera firmware information."""

    version: str
    build_date: str | None = None
    manufacturer: str | None = None
    model: str | None = None
    raw_info: dict[str, Any] = field(default_factory=dict)


@dataclass
class EnumerationResult:
    """Result of camera enumeration."""

    ip: str
    port: int
    protocol: CameraProtocol
    manufacturer: str | None = None
    model: str | None = None
    firmware: CameraFirmware | None = None
    config: CameraConfig | None = None
    credentials: list[CameraCredential] = field(default_factory=list)
    rtsp_streams: list[dict[str, Any]] = field(default_factory=list)
    onvif_info: dict[str, Any] | None = None
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    errors: list[str] = field(default_factory=list)


# Common default credentials for IP cameras
DEFAULT_CAMERA_CREDS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "1234"),
    ("admin", "888888"),
    ("admin", ""),
    ("admin", "password"),
    ("root", "root"),
    ("root", "admin"),
    ("root", "12345"),
    ("root", "123456"),
    ("root", ""),
    ("ubnt", "ubnt"),
    ("admin", "12345678"),
    ("admin", "111111"),
    ("admin", "666666"),
    ("admin", "888888"),
    ("admin", "999999"),
    ("supervisor", "supervisor"),
    ("supervisor", ""),
    ("operator", "operator"),
    ("user", "user"),
    ("guest", "guest"),
    ("cam", "cam"),
    ("camera", "camera"),
    ("dvr", "dvr"),
    ("nvr", "nvr"),
    ("service", "service"),
    ("service", "service"),
    ("tech", "tech"),
    ("tech", "tech"),
]

# Manufacturer-specific default credentials
MANUFACTURER_CREDS = {
    "hikvision": [
        ("admin", "12345"),
        ("admin", "123456"),
        ("admin", "12345678"),
        ("admin", "admin123"),
    ],
    "dahua": [("admin", "admin"), ("admin", "123456"), ("admin", "12345678"), ("admin", "888888")],
    "axis": [("root", "pass"), ("root", "root"), ("root", ""), ("admin", "admin")],
    "foscam": [("admin", ""), ("admin", "admin"), ("admin", "123456")],
    "amcrest": [("admin", "admin"), ("admin", "123456"), ("admin", "12345678")],
    "reolink": [("admin", ""), ("admin", "admin"), ("admin", "123456")],
    "tp-link": [("admin", "admin"), ("admin", "123456"), ("admin", "12345678")],
    "ubiquiti": [("ubnt", "ubnt"), ("admin", "admin"), ("admin", "123456")],
    "uniview": [("admin", "123456"), ("admin", "admin"), ("admin", "12345678")],
    "hanwha": [("admin", "123456"), ("admin", "12345678"), ("admin", "admin")],
    "vivotek": [("admin", "admin"), ("admin", "888888"), ("admin", "123456")],
    "panasonic": [("admin", "12345"), ("admin", "123456"), ("admin", "admin")],
    "sony": [("admin", "admin"), ("admin", "12345"), ("admin", "123456")],
    "bosch": [("service", "service"), ("admin", "admin"), ("service", "service")],
    "avigilon": [("admin", "admin"), ("admin", "123456"), ("admin", "12345678")],
    "geovision": [("admin", "admin"), ("admin", "123456"), ("admin", "888888")],
    "acti": [("admin", "123456"), ("admin", "admin"), ("admin", "12345678")],
    "moxa": [("admin", "moxa"), ("admin", "admin"), ("admin", "123456")],
    "d-link": [("admin", ""), ("admin", "admin"), ("admin", "123456")],
    "trendnet": [("admin", "admin"), ("admin", "123456"), ("admin", "password")],
    "edimax": [("admin", "1234"), ("admin", "admin"), ("admin", "123456")],
    "levelone": [("admin", "admin"), ("admin", "123456"), ("admin", "password")],
    "airlive": [("admin", "admin"), ("admin", "123456"), ("admin", "password")],
    "planet": [("admin", "admin"), ("admin", "123456"), ("admin", "password")],
    "zyxel": [("admin", "1234"), ("admin", "admin"), ("admin", "123456")],
    "cisco": [("cisco", "cisco"), ("admin", "admin"), ("admin", "cisco")],
    "netgear": [("admin", "password"), ("admin", "admin"), ("admin", "1234")],
    "linksys": [("admin", "admin"), ("admin", "123456"), ("admin", "")],
    "belkin": [("admin", "admin"), ("admin", "123456"), ("admin", "")],
    "asus": [("admin", "admin"), ("admin", "123456"), ("admin", "")],
}


class CameraEnumerator:
    """
    Deep camera enumeration and credential testing.

    Features:
    - Authentication testing (Basic/Digest/NTLM)
    - Default credential testing with manufacturer-specific lists
    - Configuration dump via ONVIF, HTTP API, CGI
    - Firmware version extraction
    - RTSP stream discovery
    - ONVIF device information
    """

    def __init__(
        self, timeout: int = 10, max_concurrent: int = 10, user_agent: str = "UrbanHackSentinel/1.0"
    ):
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self._semaphore = asyncio.Semaphore(max_concurrent)

        # Session cache
        self._sessions: dict[str, aiohttp.ClientSession] = {}

    async def _get_session(self, base_url: str) -> aiohttp.ClientSession:
        """Get or create aiohttp session for a base URL."""
        if not AIOHTTP_AVAILABLE:
            raise RuntimeError("aiohttp not available")
        parsed = urlparse(base_url)
        key = f"{parsed.scheme}://{parsed.netloc}"

        if key not in self._sessions:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(limit=10, ssl=False)
            self._sessions[key] = aiohttp.ClientSession(
                timeout=timeout, connector=connector, headers={"User-Agent": self.user_agent}
            )

        return self._sessions[key]

    async def close(self):
        """Close all sessions."""
        for session in self._sessions.values():
            await session.close()
        self._sessions.clear()

    # ============================================================
    # Authentication Testing
    # ============================================================

    async def test_credentials(
        self,
        ip: str,
        port: int,
        protocol: CameraProtocol = CameraProtocol.HTTP,
        credentials: list[tuple[str, str]] | None = None,
        path: str = "/",
    ) -> list[CameraCredential]:
        """Test credentials against camera."""
        if not AIOHTTP_AVAILABLE:
            logger.warning("aiohttp not available for credential testing")
            return []

        creds = credentials or self._get_manufacturer_credentials(None)
        base_url = f"{protocol.value}://{ip}:{port}{path}"
        verified_creds = []

        async with self._semaphore:
            session = await self._get_session(base_url)

            for username, password in creds:
                try:
                    # Test Basic Auth
                    cred = await self._try_basic_auth(session, base_url, username, password)
                    if cred:
                        verified_creds.append(cred)
                        continue

                    # Test Digest Auth
                    cred = await self._try_digest_auth(session, base_url, username, password)
                    if cred:
                        verified_creds.append(cred)
                        continue

                except Exception as e:
                    logger.debug("Credential test failed", ip=ip, user=username, error=str(e))

        return verified_creds

    async def _try_basic_auth(
        self, session: aiohttp.ClientSession, url: str, username: str, password: str
    ) -> CameraCredential | None:
        """Test Basic Authentication."""
        auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        headers = {"Authorization": f"Basic {auth}"}

        try:
            async with session.get(
                url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status == 200:
                    return CameraCredential(
                        username=username,
                        password=password,
                        auth_type=AuthType.BASIC,
                        verified=True,
                        verified_at=datetime.utcnow(),
                    )
                if resp.status == 401:
                    # Check for Digest auth challenge
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "Digest" in www_auth:
                        return await self._try_digest_auth_from_challenge(
                            session, url, www_auth, username, password
                        )
        except Exception:
            pass
        return None

    async def _try_digest_auth(
        self, session: aiohttp.ClientSession, url: str, username: str, password: str
    ) -> CameraCredential | None:
        """Test Digest Authentication (tries GET first to get challenge)."""
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                if resp.status == 401:
                    www_auth = resp.headers.get("WWW-Authenticate", "")
                    if "Digest" in www_auth:
                        return await self._try_digest_auth_from_challenge(
                            session, url, www_auth, username, password
                        )
        except Exception:
            pass
        return None

    @staticmethod
    def _parse_digest_challenge(www_auth: str) -> dict[str, str]:
        """Parse a ``WWW-Authenticate: Digest ...`` header into its parameters."""
        challenge = www_auth.split(" ", 1)[1] if " " in www_auth else www_auth
        params: dict[str, str] = {}
        for match in re.finditer(r'(\w+)=(?:"([^"]*)"|([^,]+))', challenge):
            params[match.group(1).lower()] = (
                match.group(2) if match.group(2) is not None else match.group(3).strip()
            )
        return params

    @staticmethod
    def _build_digest_header(
        username: str, password: str, method: str, uri: str, params: dict[str, str]
    ) -> str:
        """Compute an RFC 2617/7616 Digest ``Authorization`` header value."""
        realm = params.get("realm", "")
        nonce = params.get("nonce", "")
        qop = params.get("qop")
        opaque = params.get("opaque")
        algorithm = params.get("algorithm", "MD5")

        hasher = hashlib.sha256 if "SHA-256" in algorithm.upper() else hashlib.md5

        def H(data: str) -> str:
            return hasher(data.encode()).hexdigest()

        ha1 = H(f"{username}:{realm}:{password}")
        if algorithm.upper().endswith("-SESS"):
            cnonce = secrets.token_hex(8)
            ha1 = H(f"{ha1}:{nonce}:{cnonce}")
        ha2 = H(f"{method}:{uri}")

        parts = [f'username="{username}"', f'realm="{realm}"', f'nonce="{nonce}"', f'uri="{uri}"']
        if qop:
            selected_qop = qop.split(",")[0].strip()
            nc = "00000001"
            cnonce = secrets.token_hex(8)
            response = H(f"{ha1}:{nonce}:{nc}:{cnonce}:{selected_qop}:{ha2}")
            parts += [f"qop={selected_qop}", f"nc={nc}", f'cnonce="{cnonce}"']
        else:
            response = H(f"{ha1}:{nonce}:{ha2}")

        parts.append(f'response="{response}"')
        if opaque:
            parts.append(f'opaque="{opaque}"')
        parts.append(f"algorithm={algorithm}")
        return "Digest " + ", ".join(parts)

    async def _try_digest_auth_from_challenge(
        self,
        session: aiohttp.ClientSession,
        url: str,
        www_auth: str,
        username: str,
        password: str,
        method: str = "GET",
    ) -> CameraCredential | None:
        """Compute the Digest response and re-request to verify the credential."""
        params = self._parse_digest_challenge(www_auth)
        if not params.get("nonce"):
            return None

        uri = urlparse(url).path or "/"
        header = self._build_digest_header(username, password, method, uri, params)
        try:
            async with session.get(
                url, headers={"Authorization": header}, timeout=aiohttp.ClientTimeout(total=5)
            ) as resp:
                if resp.status in (200, 301, 302):
                    return CameraCredential(
                        username=username,
                        password=password,
                        auth_type=AuthType.DIGEST,
                        verified=True,
                        verified_at=datetime.utcnow(),
                        realm=params.get("realm"),
                    )
        except Exception:
            pass
        return None

    def _get_manufacturer_credentials(self, manufacturer: str | None) -> list[tuple[str, str]]:
        """Get credential list for manufacturer."""
        if manufacturer and manufacturer.lower() in MANUFACTURER_CREDS:
            # Start with manufacturer-specific creds, then fall back to defaults
            return MANUFACTURER_CREDS[manufacturer.lower()] + DEFAULT_CAMERA_CREDS
        return DEFAULT_CAMERA_CREDS

    # ============================================================
    # Configuration Dump
    # ============================================================

    async def dump_config(
        self,
        ip: str,
        port: int,
        credentials: CameraCredential | None = None,
        protocol: CameraProtocol = CameraProtocol.HTTP,
    ) -> CameraConfig | None:
        """Dump camera configuration."""
        if not AIOHTTP_AVAILABLE:
            return None

        base_url = f"{protocol.value}://{ip}:{port}"
        session = await self._get_session(base_url)
        config = CameraConfig(ip_address=ip)

        try:
            # Try ONVIF first
            onvif_config = await self._get_onvif_config(ip, port, credentials)
            if onvif_config:
                # Merge onvif_config into config
                for key, value in onvif_config.__dict__.items():
                    if value and not getattr(config, key, None):
                        setattr(config, key, value)

            # Try HTTP API
            http_config = await self._get_http_config(ip, port, credentials)
            if http_config:
                # Merge configs
                for key, value in http_config.__dict__.items():
                    if value and not getattr(config, key, None):
                        setattr(config, key, value)

            return config
        except Exception as e:
            logger.error("Config dump failed", ip=ip, error=str(e))
            return None

    async def _get_onvif_config(
        self, ip: str, port: int, credentials: CameraCredential | None = None
    ) -> CameraConfig | None:
        """Get config via ONVIF (device info + media profiles / RTSP URIs)."""
        if not ONVIF_AVAILABLE:
            return None

        username = credentials.username if credentials else ""
        password = credentials.password if credentials else ""

        def _query() -> CameraConfig:
            # onvif-zeep is synchronous; run it off the event loop.
            from onvif import ONVIFCamera

            cam = ONVIFCamera(ip, port, username, password)
            cam.update_xaddrs()
            info = cam.devicemgmt.GetDeviceInformation()
            cfg = CameraConfig(
                manufacturer=getattr(info, "Manufacturer", None),
                model=getattr(info, "Model", None),
                firmware_version=getattr(info, "FirmwareVersion", None),
                serial_number=getattr(info, "SerialNumber", None),
                ip_address=ip,
            )
            try:
                media = cam.create_media_service()
                for profile in media.GetProfiles():
                    token = getattr(profile, "token", None)
                    entry: dict[str, Any] = {"name": getattr(profile, "Name", None), "token": token}
                    try:
                        req = media.create_type("GetStreamUri")
                        req.ProfileToken = token
                        req.StreamSetup = {
                            "Stream": "RTP-Unicast",
                            "Transport": {"Protocol": "RTSP"},
                        }
                        uri = getattr(media.GetStreamUri(req), "Uri", None)
                        if uri:
                            entry["rtsp_uri"] = uri
                            cfg.rtsp_streams.append({"profile": token, "uri": uri})
                    except Exception:
                        pass
                    cfg.onvif_profiles.append(entry)
            except Exception:
                pass
            return cfg

        try:
            return await asyncio.to_thread(_query)
        except Exception as e:
            logger.debug("ONVIF config retrieval failed", ip=ip, error=str(e))
            return None

    async def _get_http_config(
        self, ip: str, port: int, credentials: CameraCredential | None = None
    ) -> CameraConfig | None:
        """Get config via HTTP API."""
        config = CameraConfig(ip_address=ip)

        # Common config endpoints
        config_endpoints = [
            "/cgi-bin/config.cgi",
            "/cgi-bin/admin/getparam.cgi",
            "/cgi-bin/getparam.cgi",
            "/api/config",
            "/api/system/info",
            "/ISAPI/System/deviceInfo",
            "/cgi-bin/hi3510/param.cgi?cmd=getserverinfo",
            "/web/cgi-bin/hi3510/param.cgi?cmd=getserverinfo",
            "/system/info",
            "/config",
        ]

        headers = {}
        if credentials and credentials.auth_type == AuthType.BASIC:
            auth = base64.b64encode(
                f"{credentials.username}:{credentials.password}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {auth}"

        headers["User-Agent"] = self.user_agent
        async with aiohttp.ClientSession(headers=headers) as session:
            for endpoint in config_endpoints:
                try:
                    url = f"http://{ip}:{port}{endpoint}"
                    async with aiohttp.ClientSession(
                        timeout=aiohttp.ClientTimeout(total=5)
                    ) as session:
                        async with session.get(url, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                            if resp.status == 200:
                                content_type = resp.headers.get("Content-Type", "")
                                if "json" in content_type:
                                    data = await resp.json()
                                    self._parse_config_json(data, config)
                                elif "xml" in content_type:
                                    text = await resp.text()
                                    self._parse_config_xml(text, config)
                                else:
                                    text = await resp.text()
                                    self._parse_config_text(text, config)
                except Exception:
                    continue

        return config

    def _parse_config_json(self, data: dict[str, Any], config: CameraConfig):
        """Parse JSON config into CameraConfig."""
        # Generic mapping
        config.raw_config.update(data)

    def _parse_config_xml(self, xml_text: str, config: CameraConfig):
        """Parse XML config into CameraConfig."""
        try:
            import xml.etree.ElementTree as ET

            root = ET.fromstring(xml_text)
            config.raw_config["xml"] = xml_text
        except Exception:
            pass

    def _parse_config_text(self, text: str, config: CameraConfig):
        """Parse text config into CameraConfig."""
        # Try to extract key=value pairs
        for line in text.split("\n"):
            if "=" in line and not line.strip().startswith("#"):
                key, _, value = line.partition("=")
                config.raw_config[key.strip()] = value.strip()

    # ============================================================
    # Firmware Version Extraction
    # ============================================================

    async def get_firmware_version(
        self, ip: str, port: int, protocol: CameraProtocol = CameraProtocol.HTTP
    ) -> CameraFirmware | None:
        """Extract firmware version."""
        firmware = await self._extract_firmware_http(ip, port)
        if not firmware:
            firmware = await self._extract_firmware_rtsp(ip, port)
        return firmware

    async def _extract_firmware_http(self, ip: str, port: int) -> CameraFirmware | None:
        """Extract firmware via HTTP."""
        if not AIOHTTP_AVAILABLE:
            return None

        endpoints = [
            "/api/system/firmware",
            "/cgi-bin/get_firmware.cgi",
            "/system/firmware",
            "/api/firmware",
            "/ISAPI/System/firmware",
            "/cgi-bin/getVersion.cgi",
            "/web/cgi-bin/hi3510/param.cgi?cmd=getversion",
        ]

        async with aiohttp.ClientSession(headers={"User-Agent": self.user_agent}) as session:
            for endpoint in endpoints:
                try:
                    async with session.get(
                        f"http://{ip}:{port}{endpoint}", timeout=aiohttp.ClientTimeout(total=5)
                    ) as resp:
                        if resp.status == 200:
                            data = (
                                await resp.json()
                                if "json" in resp.headers.get("Content-Type", "")
                                else await resp.text()
                            )
                            firmware = self._parse_firmware_data(data)
                            if firmware and firmware.version:
                                return firmware
                except Exception:
                    continue
        return None

    async def _extract_firmware_rtsp(self, ip: str, port: int) -> CameraFirmware | None:
        """Extract firmware via RTSP DESCRIBE."""
        # RTSP DESCRIBE can sometimes include firmware info
        return None

    def _parse_firmware_data(self, data: Any) -> CameraFirmware | None:
        """Parse firmware data from various formats."""
        if isinstance(data, dict):
            version = data.get("version") or data.get("firmware_version") or data.get("fw_version")
            if version:
                return CameraFirmware(
                    version=str(version),
                    manufacturer=data.get("manufacturer"),
                    model=data.get("model"),
                    raw_info=data,
                )
        elif isinstance(data, str):
            # Try regex patterns
            patterns = [
                r'version["\s:=]+([\d\.\-a-zA-Z]+)',
                r'firmware["\s:=]+([\d\.\-a-zA-Z]+)',
                r"version=([\d\.\-a-zA-Z]+)",
            ]
            for pattern in patterns:
                match = re.search(pattern, data, re.IGNORECASE)
                if match:
                    return CameraFirmware(version=match.group(1))
        return None

    # ============================================================
    # RTSP Stream Discovery
    # ============================================================

    async def discover_rtsp_streams(
        self, ip: str, ports: list[int] = [554, 8554, 1935, 8000]
    ) -> list[dict[str, Any]]:
        """Discover RTSP streams."""
        streams = []

        for port in ports:
            try:
                stream_info = await self._rtsp_describe(ip, port)
                if stream_info:
                    stream_info["port"] = port
                    streams.append(stream_info)
            except Exception:
                continue
        return streams

    async def _rtsp_describe(self, ip: str, port: int) -> dict[str, Any] | None:
        """Send RTSP DESCRIBE request."""
        try:
            # Use RTSP DESCRIBE
            reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=5)

            request = f"DESCRIBE rtsp://{ip}:{port}/ RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: {self.user_agent}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            response_text = response.decode(errors="ignore")

            writer.close()
            await writer.wait_closed()

            if "200 OK" in response_text:
                # Parse SDP
                return self._parse_sdp(response_text)
        except Exception:
            pass
        return None

    def _parse_sdp(self, sdp: str) -> dict[str, Any]:
        """Parse SDP response."""
        info = {"raw_sdp": sdp}
        for line in sdp.split("\n"):
            line = line.strip()
            if line.startswith("m="):
                # Media line
                parts = line.split()
                if len(parts) >= 4:
                    info["media_type"] = parts[1]
                    info["port"] = parts[2]
                    info["protocol"] = parts[3]
                    info["format"] = " ".join(parts[4:])
            elif line.startswith("a=control:"):
                info["control_url"] = line[10:]
            elif line.startswith("a=rtpmap:"):
                info["rtpmap"] = line[9:]
            elif line.startswith("a=fmtp:"):
                info["fmtp"] = line[7:]
        return info

    # ============================================================
    # ONVIF Device Information
    # ============================================================

    async def get_onvif_info(
        self, ip: str, port: int, credentials: CameraCredential | None = None
    ) -> dict[str, Any] | None:
        """Get ONVIF device information."""
        if not ONVIF_AVAILABLE:
            return None

        try:
            # Use ONVIF library
            # This would require proper implementation
            pass
        except Exception:
            pass
        return None

    # ============================================================
    # Full Enumeration
    # ============================================================

    async def enumerate_camera(
        self,
        ip: str,
        port: int = 80,
        protocols: list[CameraProtocol] | None = None,
        credentials: list[tuple[str, str]] | None = None,
    ) -> EnumerationResult:
        """Perform full camera enumeration."""
        protocols = protocols or [CameraProtocol.HTTP, CameraProtocol.RTSP, CameraProtocol.ONVIF]
        result = EnumerationResult(ip=ip, port=port, protocol=CameraProtocol.HTTP)

        # Test credentials
        if port in (80, 8080, 8081, 8443, 8888, 8889, 5000, 5001):
            creds = await self.test_credentials(ip, port, CameraProtocol.HTTP, credentials)
            result.credentials.extend(creds)

        # Firmware
        firmware = await self.get_firmware_version(ip, port)
        result.firmware = firmware

        # Config dump
        if result.credentials:
            config = await self.dump_config(ip, port, result.credentials[0])
            result.config = config

        # RTSP streams
        rtsp_streams = await self.discover_rtsp_streams(ip)
        result.rtsp_streams = rtsp_streams

        # ONVIF info
        onvif_info = await self.get_onvif_info(ip, port)
        result.onvif_info = onvif_info

        return result


# ============================================================
# Convenience Functions
# ============================================================


async def enumerate_camera(ip: str, port: int = 80, timeout: int = 10) -> EnumerationResult:
    """Convenience function to enumerate a single camera."""
    enumerator = CameraEnumerator(timeout=timeout)
    try:
        return await enumerator.enumerate_camera(ip, port)
    finally:
        await enumerator.close()


async def test_default_creds(ip: str, port: int) -> list[CameraCredential]:
    """Test default credentials against a camera."""
    enumerator = CameraEnumerator()
    try:
        return await enumerator.test_credentials(ip, port, CameraProtocol.HTTP)
    finally:
        await enumerator.close()


# ============================================================
# Exports
# ============================================================

__all__ = [
    "AuthType",
    "CameraProtocol",
    "CameraCredential",
    "CameraConfig",
    "CameraFirmware",
    "EnumerationResult",
    "DEFAULT_CAMERA_CREDS",
    "MANUFACTURER_CREDS",
    "CameraEnumerator",
    "enumerate_camera",
    "test_default_creds",
]
