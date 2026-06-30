"""
Example scanner plugin for Urban Hack Sentinel.

Demonstrates how to implement a module as an UrbanPlugin.
"""

from __future__ import annotations

from urban_hs.core.plugins import PluginType, UrbanPlugin, urban_plugin


@urban_plugin(
    name="example_sniffer",
    version="1.0.0",
    description="Example passive sniffer plugin.",
    author="urban-sentinel",
    plugin_type=PluginType.SCANNER,
    provides=["passive_scan"],
    config_schema={"duration_seconds": {"type": "integer", "default": 10}},
)
class ExampleSnifferPlugin(UrbanPlugin):
    """Passive sniffer placeholder."""

    async def initialize(self) -> bool:
        self.logger.info("example_sniffer initialized", config=self.config)
        return True

    async def start(self) -> bool:
        self.logger.info("example_sniffer started")
        return True

    async def stop(self) -> bool:
        self.logger.info("example_sniffer stopped")
        return True
