"""
Example reporter plugin for Urban Hack Sentinel.

Demonstrates how to implement a reporting module as an UrbanPlugin.
"""

from __future__ import annotations

from typing import Any, Dict

from urban_hs.core.plugins import PluginType, UrbanPlugin, urban_plugin


@urban_plugin(
    name="example_reporter",
    version="1.0.0",
    description="Example plain-text report exporter.",
    author="urban-sentinel",
    plugin_type=PluginType.REPORTER,
    provides=["report_export"],
    config_schema={"output_dir": {"type": "string", "default": "./reports"}},
)
class ExampleReporterPlugin(UrbanPlugin):
    """Minimal reporter placeholder."""

    async def initialize(self) -> bool:
        self.logger.info("example_reporter initialized", config=self.config)
        return True

    async def start(self) -> bool:
        self.logger.info("example_reporter started")
        return True

    async def stop(self) -> bool:
        self.logger.info("example_reporter stopped")
        return True
