"""
MAC anonymisation utilities.

Provides:
- Stable per-MAC pseudonymisation (same input => same output within a session)
- Format-preserving transformations for common MAC representations
- Scoped redaction for device/network/ble records and exports
"""

from __future__ import annotations

import hashlib
import re
import structlog
from typing import Any, Dict, Optional, Union

logger = structlog.get_logger(__name__)

_MAC_RE = re.compile(r"(?i)([0-9a-f]{2}(?::[0-9a-f]{2}){5})")
_HEX8_RE = re.compile(r"(?i)\b([0-9a-f]{12})\b")

# deterministic, non-reversible transform within a session
# production deployments should rotate this key per session/day


def _hmac_hex(key: bytes, value: str) -> str:
    h = hashlib.blake2b(key=key, digest_size=6)
    h.update(value.encode("utf-8"))
    return h.hexdigest()[:12].upper()


_MAC_KEY = b"urban-hs-mac:v1"


def _pseudonymise_mac_raw(mac: str) -> str:
    mac = mac.strip()
    if not mac:
        return mac
    digest = _hmac_hex(_MAC_KEY, mac.lower())
    return f"{digest[:2]}:{digest[2:4]}:{digest[4:6]}:{digest[6:8]}:{digest[8:10]}:{digest[10:12]}"


def _pseudonymise_mac(mac: Optional[str]) -> str:
    if not mac:
        return ""
    return _pseudonymise_mac_raw(mac)


def pseudonymise_mac(mac: Optional[str]) -> str:
    if not mac:
        return mac if mac is not None else ""
    return _pseudonymise_mac(mac)


# Helpers that keep caller-visible signatures closer to the original modules.


def pseudonymise_macs(value: Any) -> Any:
    if isinstance(value, dict):
        out: Dict[str, Any] = {}
        for k, v in value.items():
            lowered = k.lower()
            if lowered in {"mac", "bssid", "address", "source", "destination", "client", "device_id"}:
                out[k] = pseudonymise_mac(v if isinstance(v, str) else None)
            else:
                out[k] = pseudonymise_macs(v)
        return out
    if isinstance(value, list):
        return [pseudonymise_macs(item) for item in value]
    if isinstance(value, str):
        if _MAC_RE.search(value) or _HEX8_RE.search(value):
            return _MAC_RE.sub(lambda m: pseudonymise_mac(m.group(0)), value)
        return value
    return value


def redact_text(text: str) -> str:
    if not text:
        return text
    return _MAC_RE.sub(lambda m: pseudonymise_mac(m.group(0)), text)




