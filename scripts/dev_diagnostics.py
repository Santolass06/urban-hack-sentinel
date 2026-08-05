#!/usr/bin/env python3
"""
Urban Hack Sentinel — Developer Diagnostics & Debug Collector

Gathers runtime metrics, environment configs, database state, log extracts,
and hardware capabilities into a timestamped debug bundle for easy troubleshooting.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def collect_diagnostics() -> Path:
    out_dir = Path.home() / ".local/share/urban-hs/dev_debug"
    out_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    bundle_dir = out_dir / f"diag_{timestamp}"
    bundle_dir.mkdir(parents=True, exist_ok=True)

    # 1. System & Environment Info
    env_info = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": platform.python_version(),
        "executable": sys.executable,
        "platform": platform.platform(),
        "architecture": platform.machine(),
        "cwd": os.getcwd(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
    }

    # 2. Tools Probe
    tools = [
        "iw", "aircrack-ng", "aireplay-ng", "airodump-ng", "hcxdumptool",
        "hcxpcapngtool", "reaver", "pixiewps", "nmap", "bluez", "bluetoothctl", "gpsd"
    ]
    env_info["tools_installed"] = {t: shutil.which(t) is not None for t in tools}

    (bundle_dir / "system_info.json").write_text(
        json.dumps(env_info, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # 3. Collect Recent Logs if available
    log_locations = [
        Path("/var/log/urban-hs"),
        Path.home() / ".local/share/urban-hs/logs",
        Path(".gemini/antigravity-cli/brain"),
    ]
    logs_dir = bundle_dir / "logs"
    logs_dir.mkdir(exist_ok=True)

    for loc in log_locations:
        if loc.exists() and loc.is_dir():
            for log_file in loc.glob("*.log"):
                try:
                    shutil.copy2(log_file, logs_dir / log_file.name)
                except Exception:
                    pass

    # 4. Storage & Database Status
    db_file = Path.home() / ".local/share/urban-hs/urban_hs.db"
    db_info = {
        "db_exists": db_file.exists(),
        "db_size_bytes": db_file.stat().st_size if db_file.exists() else 0,
    }
    (bundle_dir / "database_info.json").write_text(
        json.dumps(db_info, indent=2), encoding="utf-8"
    )

    print(f"[✔] Bundle de diagnóstico de desenvolvimento criado em: {bundle_dir}")
    return bundle_dir


if __name__ == "__main__":
    collect_diagnostics()
