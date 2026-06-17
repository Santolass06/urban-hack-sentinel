"""
Camera Module - IP Camera enumeration, vulnerability assessment, and exploitation.

Provides:
- Camera discovery (mDNS, UPnP, ONVIF, RTSP, HTTP)
- Camera enumeration (Auth test, default creds, config dump, firmware)
- Camera vulnerability checking (CVE mapping, exploit availability)
"""

from urban_hs.modules.camera.enumeration import (
    AuthType,
    CameraProtocol,
    CameraCredential,
    CameraConfig,
    CameraFirmware,
    EnumerationResult,
    DEFAULT_CAMERA_CREDS,
    MANUFACTURER_CREDS,
    CameraEnumerator,
    enumerate_camera,
    test_default_creds,
)

from urban_hs.modules.camera.vuln_check import (
    CameraVulnChecker,
    CameraVulnerability,
    DEFAULT_CVE_DB,
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