"""PluginManager is the third-party extension path — prove it actually loads.

Core modules are wired directly in the API lifespan for control/performance;
PluginManager is the documented way to drop in *additional* modules via the
UrbanPlugin interface. This exercises that path with the shipped example
plugin, so it is a live, tested subsystem rather than dead code.
"""

from __future__ import annotations

import pytest

from urban_hs.core.plugins import PluginStatus, create_plugin_manager
from urban_hs.modules.plugins.example_sniffer import ExampleSnifferPlugin


@pytest.mark.asyncio
async def test_plugin_manager_loads_example_plugin() -> None:
    manager = create_plugin_manager()
    meta = ExampleSnifferPlugin.metadata
    manager._plugin_classes[meta.name] = ExampleSnifferPlugin

    loaded = await manager.load_plugin(meta)

    assert loaded is True
    assert meta.name in manager._plugins
    assert manager._plugins[meta.name].status == PluginStatus.LOADED
    assert isinstance(manager._plugins[meta.name].instance, ExampleSnifferPlugin)
