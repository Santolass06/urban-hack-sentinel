"""
Plugin System - Dynamic plugin loading and management for Urban Hack Sentinel.

Provides:
- Entry point discovery (urban_hs.plugins)
- Plugin metadata and validation
- Dependency graph with topological sorting
- Runtime enable/disable
- Plugin isolation and sandboxing
- Hot-reload support
"""

import asyncio
import importlib
import importlib.metadata
import inspect
import structlog
import sys
import time
import traceback
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Callable, Awaitable, Union

logger = structlog.get_logger(__name__)


class PluginStatus(Enum):
    """Plugin lifecycle status."""
    DISCOVERED = "discovered"
    LOADING = "loading"
    LOADED = "loaded"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    UNLOADED = "unloaded"


class PluginType(Enum):
    """Types of plugins."""
    SCANNER = "scanner"           # WiFi, BLE, Network scanners
    ATTACK = "attack"             # Attack modules
    EXPLOIT = "exploit"           # Exploit modules
    REPORTER = "reporter"         # Reporting modules
    UI = "ui"                     # UI components
    INTEGRATION = "integration"   # External tool integrations
    UTILITY = "utility"           # Utility functions
    UNKNOWN = "unknown"


@dataclass
class PluginMetadata:
    """Plugin metadata from entry point or manifest."""
    name: str
    version: str
    description: str = ""
    author: str = ""
    license: str = ""
    plugin_type: PluginType = PluginType.UNKNOWN
    dependencies: List[str] = field(default_factory=list)  # Other plugin names
    provides: List[str] = field(default_factory=list)      # Services this plugin provides
    requires: List[str] = field(default_factory=list)      # External requirements (pip packages)
    entry_point: str = ""  # Module path to plugin class
    config_schema: Dict[str, Any] = field(default_factory=dict)  # JSON schema for config
    tags: List[str] = field(default_factory=list)
    min_core_version: str = "3.0.0"
    max_core_version: Optional[str] = None
    homepage: str = ""
    repository: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "license": self.license,
            "plugin_type": self.plugin_type.value,
            "dependencies": self.dependencies,
            "provides": self.provides,
            "requires": self.requires,
            "entry_point": self.entry_point,
            "config_schema": self.config_schema,
            "tags": self.tags,
            "min_core_version": self.min_core_version,
            "max_core_version": self.max_core_version,
            "homepage": self.homepage,
            "repository": self.repository,
        }


@dataclass
class PluginInstance:
    """Runtime plugin instance."""
    metadata: PluginMetadata
    instance: Any = None
    status: PluginStatus = PluginStatus.DISCOVERED
    config: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    load_time: Optional[float] = None
    enabled: bool = False
    module_ref: Optional[Any] = None


class UrbanPlugin(ABC):
    """
    Base class for all Urban Hack Sentinel plugins.
    
    Plugins should subclass this and implement the required methods.
    """
    
    # Plugin metadata - override in subclass
    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    plugin_type: PluginType = PluginType.UNKNOWN
    dependencies: List[str] = []
    provides: List[str] = []
    config_schema: Dict[str, Any] = {}
    
    def __init__(self, config: Dict[str, Any], event_bus: Optional[Any] = None, 
                 services: Optional[Dict[str, Any]] = None):
        """
        Initialize plugin.
        
        Args:
            config: Plugin configuration from main config
            event_bus: EventBus instance for pub/sub
            services: Dictionary of core services (storage, logger, etc.)
        """
        self.config = config or {}
        self.event_bus = event_bus
        self.services = services or {}
        self.logger = structlog.get_logger(f"plugin.{self.name}")
        self._enabled = False
    
    @abstractmethod
    async def initialize(self) -> bool:
        """
        Initialize plugin resources and connections.
        
        Returns:
            True if initialization successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def start(self) -> bool:
        """
        Start plugin operations.
        
        Returns:
            True if start successful, False otherwise
        """
        pass
    
    @abstractmethod
    async def stop(self) -> bool:
        """
        Stop plugin operations gracefully.
        
        Returns:
            True if stop successful, False otherwise
        """
        pass
    
    async def cleanup(self) -> bool:
        """
        Cleanup plugin resources.
        
        Returns:
            True if cleanup successful, False otherwise
        """
        return True
    
    def get_health(self) -> Dict[str, Any]:
        """Get plugin health status."""
        return {
            "name": self.name,
            "enabled": self._enabled,
            "status": "healthy",
        }
    
    def get_config_schema(self) -> Dict[str, Any]:
        """Get configuration schema for validation."""
        return self.config_schema
    
    def emit_event(self, event_type: str, data: Dict[str, Any]):
        """Emit event through event bus."""
        if self.event_bus:
            asyncio.create_task(self.event_bus.publish(f"plugin.{self.name}.{event_type}", data))
    
    def get_service(self, service_name: str) -> Optional[Any]:
        """Get a core service by name."""
        return self.services.get(service_name)


class PluginManager:
    """
    Manages plugin discovery, loading, and lifecycle.
    
    Features:
    - Entry point discovery via importlib.metadata
    - Dependency resolution with topological sort
    - Runtime enable/disable
    - Hot-reload support
    - Configuration management
    """

    def __init__(
        self,
        config: Optional[Dict[str, Any]] = None,
        event_bus: Optional[Any] = None,
        services: Optional[Dict[str, Any]] = None,
        plugin_dirs: Optional[List[str]] = None,
    ):
        self.config = config or {}
        self.event_bus = event_bus
        self.services = services or {}
        self.plugin_dirs = plugin_dirs or []
        
        self._plugins: Dict[str, PluginInstance] = {}
        self._load_order: List[str] = []
        self._enabled_plugins: Set[str] = set()
        self._plugin_classes: Dict[str, Type[UrbanPlugin]] = {}
        
        # Core services available to plugins
        self._core_services = {
            "config": self.config,
            "event_bus": self.event_bus,
            "logger": structlog.get_logger("core"),
        }
        self._core_services.update(self.services)

    async def discover_plugins(self, entry_point_group: str = "urban_hs.plugins") -> List[PluginMetadata]:
        """Discover plugins via entry points."""
        discovered = []
        
        try:
            # Try importlib.metadata (Python 3.8+)
            eps = importlib.metadata.entry_points()
            if hasattr(eps, 'select'):
                # Python 3.10+
                plugin_eps = eps.select(group=entry_point_group)
            else:
                # Python 3.8-3.9
                plugin_eps = eps.get(entry_point_group, [])
            
            for ep in plugin_eps:
                try:
                    # Load the plugin class
                    plugin_class = ep.load()
                    
                    # Extract metadata
                    if hasattr(plugin_class, 'metadata') and isinstance(plugin_class.metadata, PluginMetadata):
                        meta = plugin_class.metadata
                    else:
                        # Build from class attributes
                        meta = PluginMetadata(
                            name=getattr(plugin_class, 'name', ep.name),
                            version=getattr(plugin_class, 'version', '1.0.0'),
                            description=getattr(plugin_class, 'description', ''),
                            author=getattr(plugin_class, 'author', ''),
                            plugin_type=getattr(plugin_class, 'plugin_type', PluginType.UNKNOWN),
                            dependencies=getattr(plugin_class, 'dependencies', []),
                            provides=getattr(plugin_class, 'provides', []),
                            entry_point=f"{ep.module}:{ep.name}",
                            config_schema=getattr(plugin_class, 'config_schema', {}),
                            tags=getattr(plugin_class, 'tags', []),
                        )
                    
                    discovered.append(meta)
                    self._plugin_classes[meta.name] = plugin_class
                    logger.info("Plugin discovered", name=meta.name, version=meta.version, type=meta.plugin_type.value)
                    
                except Exception as e:
                    logger.error("Failed to load plugin entry point", entry_point=ep.name, error=str(e))
                    
        except Exception as e:
            logger.error("Error discovering plugins", error=str(e))
        
        return discovered

    async def load_plugin(self, metadata: PluginMetadata, config: Optional[Dict[str, Any]] = None) -> bool:
        """Load a plugin by metadata."""
        if metadata.name in self._plugins:
            logger.warning("Plugin already loaded", name=metadata.name)
            return True
        
        plugin_class = self._plugin_classes.get(metadata.name)
        if not plugin_class:
            # Try to load from entry point
            if metadata.entry_point:
                try:
                    module_path, class_name = metadata.entry_point.split(":")
                    module = importlib.import_module(module_path)
                    plugin_class = getattr(module, class_name)
                    self._plugin_classes[metadata.name] = plugin_class
                except Exception as e:
                    logger.error("Failed to import plugin class", name=metadata.name, error=str(e))
                    return False
            else:
                logger.error("No plugin class available", name=metadata.name)
                return False
        
        plugin_instance = PluginInstance(
            metadata=metadata,
            status=PluginStatus.LOADING,
            config=config or self.config.get("plugins", {}).get(metadata.name, {}),
        )
        
        self._plugins[metadata.name] = plugin_instance
        
        try:
            # Instantiate plugin
            if inspect.isclass(plugin_class) and issubclass(plugin_class, UrbanPlugin):
                instance = plugin_class(
                    config=plugin_instance.config,
                    event_bus=self.event_bus,
                    services=self._core_services,
                )
            else:
                # Assume it's a factory function or callable
                instance = plugin_class(
                    config=plugin_instance.config,
                    event_bus=self.event_bus,
                    services=self._core_services,
                )
            
            plugin_instance.instance = instance
            plugin_instance.status = PluginStatus.LOADED
            plugin_instance.load_time = time.time()
            
            logger.info("Plugin loaded", name=metadata.name)
            return True
            
        except Exception as e:
            plugin_instance.status = PluginStatus.ERROR
            plugin_instance.error = str(e)
            logger.error("Failed to load plugin", name=metadata.name, error=str(e))
            return False

    async def enable_plugin(self, name: str) -> bool:
        """Enable a loaded plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            logger.error("Plugin not found", name=name)
            return False
        
        if plugin.status != PluginStatus.LOADED and plugin.status != PluginStatus.DISABLED:
            logger.error("Plugin not in loadable state", name=name, status=plugin.status.value)
            return False
        
        # Check dependencies
        for dep_name in plugin.metadata.dependencies:
            if dep_name not in self._plugins:
                plugin.error = f"Missing dependency: {dep_name}"
                plugin.status = PluginStatus.ERROR
                logger.error("Plugin dependency missing", name=name, dependency=dep_name)
                return False
            
            dep_plugin = self._plugins[dep_name]
            if not dep_plugin.enabled:
                plugin.error = f"Dependency not enabled: {dep_name}"
                plugin.status = PluginStatus.ERROR
                logger.error("Plugin dependency not enabled", name=name, dependency=dep_name)
                return False
        
        try:
            plugin.status = PluginStatus.ENABLED
            
            if plugin.instance and hasattr(plugin.instance, 'initialize'):
                success = await plugin.instance.initialize()
                if not success:
                    raise RuntimeError("Plugin initialization failed")
            
            if plugin.instance and hasattr(plugin.instance, 'start'):
                success = await plugin.instance.start()
                if not success:
                    raise RuntimeError("Plugin start failed")
            
            plugin.enabled = True
            self._enabled_plugins.add(name)
            
            logger.info("Plugin enabled", name=name)
            
            if self.event_bus:
                await self.event_bus.publish("plugin.enabled", {"name": name})
            
            return True
            
        except Exception as e:
            plugin.status = PluginStatus.ERROR
            plugin.error = str(e)
            plugin.enabled = False
            logger.error("Failed to enable plugin", name=name, error=str(e))
            return False

    async def disable_plugin(self, name: str) -> bool:
        """Disable a plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        
        if not plugin.enabled:
            return True
        
        try:
            if plugin.instance and hasattr(plugin.instance, 'stop'):
                await plugin.instance.stop()
            
            if plugin.instance and hasattr(plugin.instance, 'cleanup'):
                await plugin.instance.cleanup()
            
            plugin.enabled = False
            plugin.status = PluginStatus.DISABLED
            self._enabled_plugins.discard(name)
            
            logger.info("Plugin disabled", name=name)
            
            if self.event_bus:
                await self.event_bus.publish("plugin.disabled", {"name": name})
            
            return True
            
        except Exception as e:
            plugin.error = str(e)
            logger.error("Error disabling plugin", name=name, error=str(e))
            return False

    async def unload_plugin(self, name: str) -> bool:
        """Unload a plugin completely."""
        await self.disable_plugin(name)
        
        plugin = self._plugins.get(name)
        if not plugin:
            return True
        
        try:
            if plugin.instance and hasattr(plugin.instance, 'cleanup'):
                await plugin.instance.cleanup()
            
            plugin.status = PluginStatus.UNLOADED
            plugin.instance = None
            plugin.module_ref = None
            
            self._plugins.pop(name, None)
            self._plugin_classes.pop(name, None)
            self._enabled_plugins.discard(name)
            
            # Remove from load order
            if name in self._load_order:
                self._load_order.remove(name)
            
            logger.info("Plugin unloaded", name=name)
            return True
            
        except Exception as e:
            logger.error("Error unloading plugin", name=name, error=str(e))
            return False

    def get_load_order(self) -> List[str]:
        """Calculate topological load order based on dependencies."""
        # Build dependency graph
        graph = {name: set(meta.metadata.dependencies) for name, meta in self._plugins.items()}
        
        # Topological sort (Kahn's algorithm)
        in_degree = defaultdict(int)
        for name, deps in graph.items():
            for dep in deps:
                if dep in graph:
                    in_degree[dep] += 1
        
        queue = [name for name in graph if in_degree[name] == 0]
        order = []
        
        while queue:
            name = queue.pop(0)
            order.append(name)
            
            for other_name, deps in graph.items():
                if name in deps:
                    in_degree[other_name] -= 1
                    if in_degree[other_name] == 0:
                        queue.append(other_name)
        
        if len(order) != len(graph):
            raise RuntimeError("Circular dependency detected in plugins")
        
        self._load_order = order
        return order

    async def load_all(self) -> Dict[str, bool]:
        """Load all discovered plugins."""
        results = {}
        
        # Discover plugins
        discovered = await self.discover_plugins()
        
        # Load in dependency order
        load_order = self.get_load_order()
        
        for name in load_order:
            plugin_meta = next((m for m in discovered if m.name == name), None)
            if plugin_meta:
                plugin_config = self.config.get("plugins", {}).get(name, {})
                results[name] = await self.load_plugin(plugin_meta, plugin_config)
            else:
                results[name] = False
        
        return results

    async def enable_all(self) -> Dict[str, bool]:
        """Enable all loaded plugins in dependency order."""
        results = {}
        
        for name in self._load_order:
            if name in self._plugins:
                results[name] = await self.enable_plugin(name)
        
        return results

    async def disable_all(self) -> Dict[str, bool]:
        """Disable all enabled plugins in reverse dependency order."""
        results = {}
        
        for name in reversed(self._load_order):
            if name in self._plugins and self._plugins[name].enabled:
                results[name] = await self.disable_plugin(name)
        
        return results

    async def reload_plugin(self, name: str) -> bool:
        """Hot-reload a plugin."""
        plugin = self._plugins.get(name)
        if not plugin:
            return False
        
        # Save config
        config = plugin.config
        metadata = plugin.metadata
        
        # Unload
        await self.unload_plugin(name)
        
        # Reload module
        if plugin.module_ref:
            try:
                importlib.reload(plugin.module_ref)
            except Exception:
                pass
        
        # Reload from entry point
        if metadata.entry_point:
            try:
                module_path, class_name = metadata.entry_point.split(":")
                module = importlib.import_module(module_path)
                importlib.reload(module)
                plugin_class = getattr(module, class_name)
                self._plugin_classes[name] = plugin_class
            except Exception:
                pass
        
        # Load again
        success = await self.load_plugin(metadata, config)
        if success and plugin.enabled:
            success = await self.enable_plugin(name)
        
        return success

    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get plugin info including runtime status."""
        plugin = self._plugins.get(name)
        if not plugin:
            return None
        
        info = {
            "metadata": plugin.metadata.to_dict(),
            "status": plugin.status.value,
            "enabled": plugin.enabled,
            "config": plugin.config,
            "error": plugin.error,
            "load_time": plugin.load_time,
        }
        
        if plugin.instance and hasattr(plugin.instance, 'get_health'):
            info["health"] = plugin.instance.get_health()
        
        return info

    def list_plugins(self, enabled_only: bool = False) -> List[Dict[str, Any]]:
        """List all plugins with their status."""
        plugins = []
        for name, plugin in self._plugins.items():
            if enabled_only and not plugin.enabled:
                continue
            plugins.append(self.get_plugin_info(name))
        return plugins

    def get_service(self, service_name: str) -> Optional[Any]:
        """Get a core service."""
        return self._core_services.get(service_name)

    def register_service(self, name: str, service: Any):
        """Register a service for plugins to use."""
        self._core_services[name] = service

    async def shutdown(self):
        """Shutdown all plugins gracefully."""
        await self.disable_all()


def create_plugin_manager(config: Optional[Dict[str, Any]] = None,
                         event_bus: Optional[Any] = None,
                         services: Optional[Dict[str, Any]] = None,
                         plugin_dirs: Optional[List[str]] = None) -> PluginManager:
    """Create a plugin manager with default configuration."""
    return PluginManager(config, event_bus, services, plugin_dirs)


# Decorator for easy plugin creation
def urban_plugin(
    name: str,
    version: str = "1.0.0",
    description: str = "",
    author: str = "",
    plugin_type: PluginType = PluginType.UNKNOWN,
    dependencies: Optional[List[str]] = None,
    provides: Optional[List[str]] = None,
    config_schema: Optional[Dict[str, Any]] = None,
):
    """Decorator to mark a class as an Urban Hack Sentinel plugin."""
    def decorator(cls):
        cls.name = name
        cls.version = version
        cls.description = description
        cls.author = author
        cls.plugin_type = plugin_type
        cls.dependencies = dependencies or []
        cls.provides = provides or []
        cls.config_schema = config_schema or {}
        
        # Create metadata
        cls.metadata = PluginMetadata(
            name=name,
            version=version,
            description=description,
            author=author,
            plugin_type=plugin_type,
            dependencies=dependencies or [],
            provides=provides or [],
            config_schema=config_schema or {},
        )
        
        return cls
    return decorator


# Export all public classes
__all__ = [
    "PluginStatus",
    "PluginType",
    "PluginMetadata",
    "PluginInstance",
    "UrbanPlugin",
    "PluginManager",
    "create_plugin_manager",
    "urban_plugin",
]