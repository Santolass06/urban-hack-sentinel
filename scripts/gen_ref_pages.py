#!/usr/bin/env python3
"""
Generate MkDocs reference pages from source code.
"""
import asyncio
import os
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

async def generate_reference_pages():
    """Generate reference pages for all modules."""
    modules_to_document = [
        "urban_hs.core",
        "urban_hs.core.config",
        "urban_hs.core.event_bus",
        "urban_hs.core.process_mgr",
        "urban_hs.core.storage",
        "urban_hs.core.health",
        "urban_hs.core.scheduler",
        "urban_hs.core.plugins",
        "urban_hs.core.concurrency",
        "urban_hs.core.memory",
        "urban_hs.core.security",
        "urban_hs.modules.wifi",
        "urban_hs.modules.ble",
        "urban_hs.modules.network",
        "urban_hs.modules.camera",
        "urban_hs.modules.metasploit",
        "urban_hs.modules.exploit",
        "urban_hs.modules.hid",
        "urban_hs.modules.usb",
        "urban_hs.modules.reporting",
        "urban_hs.modules.wifi",
        "urban_hs.modules.bt_hid",
        "urban_hs.modules.esp32",
        "urban_hs.modules.ssid_confusion",
        "urban_hs.modules.mqtt",
        "urban_hs.modules.credential",
        "urban_hs.modules.reporting",
    ]
    
    output_dir = Path(__file__).parent.parent / "docs" / "reference"
    output_dir.mkdir(parents=True, exist_ok=True)
    
    for module_name in modules_to_document:
        try:
            module = __import__(module_name, fromlist=[''])
            page = output_dir / f"{module_name.replace('.', '_')}.md"
            with open(page, 'w') as f:
                f.write(f"# {module_name}\n\n")
                f.write(f"::: {module_name}\n")
            print(f"Generated: {page}")
        except Exception as e:
            print(f"Failed to generate {module_name}: {e}")

if __name__ == "__main__":
    asyncio.run(generate_reference_pages())