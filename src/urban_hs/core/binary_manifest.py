"""
Binary integrity — module allowlists and SHA256 manifest validation.

Provides:
- Static manifest of trusted external binaries per module/tool
- Startup/on-demand check that the binary exists and matches expected hash
- Safe environments: when verification is explicitly disabled or no hash is
  configured for a given key, the check is skipped instead of failing hard.
"""

from __future__ import annotations

import hashlib
import os
import structlog
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Optional

logger = structlog.get_logger(__name__)


@dataclass
class BinaryRecord:
    """Expected binary metadata for integrity checks."""

    name: str
    path: str
    sha256: Optional[str] = None  # hex digest; empty means not enforced
    description: str = ""


@dataclass
class BinaryManifest:
    """Registry of trusted binaries grouped by logical key."""

    records: Dict[str, BinaryRecord] = field(default_factory=dict)

    def add(self, record: BinaryRecord) -> None:
        self.records[record.name] = record

    def get(self, name: str) -> Optional[BinaryRecord]:
        return self.records.get(name)


class BinaryVerifier:
    """Validates installed binaries against manifest expectations."""

    def __init__(
        self,
        manifest: Optional[BinaryManifest] = None,
        enforcement: str = "warn",
    ):
        """
        Args:
            manifest: Known-good binary registry.
            enforcement:
                - "enforce": failures raise RuntimeError
                - "warn": failures log warnings and return False
                - "skip": no checks are performed
        """
        self.manifest = manifest or BinaryManifest()
        self.enforcement = enforcement

    def resolve_path(self, name: str) -> Optional[str]:
        """Resolve a binary name to an absolute path using PATH."""
        record = self.manifest.get(name)
        if record is None:
            return None
        path = Path(record.path)
        if path.is_absolute():
            return str(path) if path.exists() else None
        # Search PATH for bare command names
        abs_path = shutil_which(name)
        return abs_path

    def sha256_of(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as exc:
            logger.warning("Binary hash failed", path=path, error=str(exc))
            return None

    def check(self, name: str) -> bool:
        """Verify a single binary entry from the manifest."""
        record = self.manifest.get(name)
        if record is None:
            logger.debug("Binary manifest skip: no entry", name=name)
            return True

        if self.enforcement == "skip" or not record.sha256:
            return True

        path = self.resolve_path(name)
        if not path or not os.path.exists(path):
            logger.warning(
                "Binary not found", name=name, expected=record.path, record=record
            )
            return self._handle_failure(name, "missing")

        actual = self.sha256_of(path)
        if actual is None:
            logger.warning("Binary unreadable", name=name, path=path)
            return self._handle_failure(name, "unreadable")

        if actual != record.sha256:
            logger.warning(
                "Binary hash mismatch",
                name=name,
                path=path,
                expected=record.sha256,
                actual=actual,
            )
            return self._handle_failure(name, "mismatch")

        logger.debug("Binary verified", name=name, path=path)
        return True

    def check_all(self) -> Dict[str, bool]:
        return {name: self.check(name) for name in self.manifest.records}

    def _handle_failure(self, name: str, reason: str) -> bool:
        if self.enforcement == "enforce":
            raise RuntimeError(
                f"Binary integrity check failed for {name}: {reason}"
            )
        return False


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_aircrack_ng() -> str:
    """Try common install locations for aircrack-ng."""
    candidates = [
        "/usr/local/sbin/airodump-ng",
        "/usr/local/bin/airodump-ng",
        "/usr/sbin/airodump-ng",
        "/usr/bin/airodump-ng",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return "airodump-ng"


def _detect_hcxdumptool() -> str:
    candidates = [
        "/usr/local/sbin/hcxdumptool",
        "/usr/local/bin/hcxdumptool",
        "/usr/sbin/hcxdumptool",
        "/usr/bin/hcxdumptool",
        "/usr/local/bin/hcxdump",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path
    return "hcxdumptool"


def build_manifest() -> BinaryManifest:
    manifest = BinaryManifest()
    # WiFi toolkit
    manifest.add(
        BinaryRecord(
            name="airodump-ng",
            path=_detect_aircrack_ng(),
            description="Aircrack-ng capture tool",
        )
    )
    manifest.add(
        BinaryRecord(
            name="aireplay-ng",
            path=shutil_which("aireplay-ng") or "aireplay-ng",
            description="Aircrack-ng injection tool",
        )
    )
    manifest.add(
        BinaryRecord(
            name="aircrack-ng",
            path=shutil_which("aircrack-ng") or "aircrack-ng",
            description="WPA/WPA2 cracker",
        )
    )
    manifest.add(
        BinaryRecord(
            name="hcxdumptool",
            path=_detect_hcxdumptool(),
            description="PMKID/handshake capture",
        )
    )
    manifest.add(
        BinaryRecord(
            name="hcxpcapngtool",
            path=shutil_which("hcxpcapngtool") or "hcxpcapngtool",
            description="PCAP to hash converter",
        )
    )
    manifest.add(
        BinaryRecord(
            name="reaver",
            path=shutil_which("reaver") or "reaver",
            description="WPS Pixie Dust / PIN attacks",
        )
    )
    manifest.add(
        BinaryRecord(
            name="bully",
            path=shutil_which("bully") or "bully",
            description="WPS PIN brute-force alternative",
        )
    )
    manifest.add(
        BinaryRecord(
            name="macchanger",
            path=shutil_which("macchanger") or "macchanger",
            description="MAC OUI randomization",
        )
    )
    manifest.add(
        BinaryRecord(
            name="iw",
            path=shutil_which("iw") or "iw",
            description="nl80211 WiFi CLI",
        )
    )
    # Network toolkit
    manifest.add(
        BinaryRecord(
            name="nmap",
            path=shutil_which("nmap") or "nmap",
            description="Network discovery scanner",
        )
    )
    manifest.add(
        BinaryRecord(
            name="nuclei",
            path=shutil_which("nuclei") or "nuclei",
            description="Vulnerability scanner",
        )
    )
    # Runtime confinement/binaries that may be present
    manifest.add(
        BinaryRecord(
            name="python3",
            path=shutil_which("python3") or "python3",
            description="Python interpreter",
        )
    )
    return manifest


# shared manifest instance
_default_manifest: Optional[BinaryManifest] = None


def get_binary_verifier(enforcement: str = "warn") -> BinaryVerifier:
    global _default_manifest
    if _default_manifest is None:
        _default_manifest = build_manifest()
    return BinaryVerifier(manifest=_default_manifest, enforcement=enforcement)


def verify_binary(name: str, verifier: Optional[BinaryVerifier] = None) -> bool:
    return (verifier or get_binary_verifier()).check(name)


def verify_required_binaries(names, verifier: Optional[BinaryVerifier] = None) -> bool:
    item = verifier or get_binary_verifier()
    results = [item.check(name) for name in names]
    return all(results)
