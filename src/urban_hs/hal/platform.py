"""
Platform and feature detection helpers.

Usage::

    from urban_hs.hal.platform import Platform, detect_platform

    p = detect_platform()
    if p.arch in ("x86_64", "x64"):
        ...
"""

from __future__ import annotations

import platform
from dataclasses import dataclass
from enum import Enum
from typing import Set


class Arch(Enum):
    ARM64 = "arm64"
    X86_64 = "x86_64"
    X86 = "x86"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Platform:
    arch: Arch
    system: str
    release: str
    python: str
    features: Set[str]

    @property
    def is_arm64(self) -> bool:
        return self.arch == Arch.ARM64

    @property
    def is_x86(self) -> bool:
        return self.arch in (Arch.X86_64, Arch.X86)

    @property
    def is_x86_64(self) -> bool:
        return self.arch == Arch.X86_64


_BADGE = {
    "aarch64": Arch.ARM64,
    "arm64": Arch.ARM64,
    "x86_64": Arch.X86_64,
    "x64": Arch.X86_64,
    "AMD64": Arch.X86_64,
    "i386": Arch.X86,
    "i686": Arch.X86,
}


def detect_platform() -> Platform:
    arch_str = platform.machine().lower()
    arch = _BADGE.get(arch_str, Arch.UNKNOWN)
    return Platform(
        arch=arch,
        system=platform.system(),
        release=platform.release(),
        python=platform.python_version(),
        features=_probe_features(),
    )


def _probe_features() -> Set[str]:
    import shutil

    tools = [
        "iw",
        "aircrack-ng",
        "hcxdumptool",
        "hcxpcapngtool",
        "reaver",
        "bully",
        "macchanger",
        "nmap",
        "nuclei",
        "msfconsole",
        "hashcat",
        "bluetoothctl",
        "btmgmt",
        "scapy",
        "bleak",
    ]
    # Best-effort Python module probe
    modules = ["scapy", "bleak", "fastapi", "textual"]
    present = {t for t in tools if shutil.which(t)}
    for mod in modules:
        try:
            __import__(mod)
            present.add(mod)
        except Exception:
            pass
    return present
