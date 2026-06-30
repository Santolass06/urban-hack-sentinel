"""
Camera Module - IP Camera enumeration, vulnerability assessment, and exploitation.

Provides:
- Camera discovery (mDNS, UPnP, ONVIF, RTSP, HTTP)
- Camera enumeration (Auth test, default creds, config dump, firmware)
- Camera vulnerability checking (CVE mapping, exploit availability)
"""

from urban_hs.modules.camera.enumeration import (
    DEFAULT_CAMERA_CREDS,
    MANUFACTURER_CREDS,
    AuthType,
    CameraConfig,
    CameraCredential,
    CameraEnumerator,
    CameraFirmware,
    CameraProtocol,
    EnumerationResult,
    enumerate_camera,
    test_default_creds,
)
from urban_hs.modules.camera.vuln_check import (
    DEFAULT_CVE_DB,
    CameraVulnChecker,
    CameraVulnerability,
    check_camera_vulnerabilities,
)

__all__ = [
    # Enumeration
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
    # Vulnerability checking
    "CameraVulnChecker",
    "CameraVulnerability",
    "DEFAULT_CVE_DB",
    "check_camera_vulnerabilities",
]