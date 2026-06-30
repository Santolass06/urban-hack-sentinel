"""
Core package - Shared infrastructure for Urban Hack Sentinel.
"""

import asyncio
from typing import Any, Dict, Optional

from urban_hs.core.concurrency import (
    ResourceConfig,
    ResourceManager,
    ResourcePool,
    ResourcePriority,
    ResourceType,
    ResourceUsage,
    get_resource_manager,
)
from urban_hs.core.config import Config, get_config, init_config, shutdown_config
from urban_hs.core.event_bus import (
    DeadLetterQueue,
    Event,
    EventBus,
    EventHandler,
    EventPriority,
    get_event_bus,
    init_event_bus,
    shutdown_event_bus,
)
from urban_hs.core.health import (
    HealthChecker,
    HealthCheckMiddleware,
    HealthCheckResult,
    HealthStatus,
    SystemMetrics,
    create_health_checker,
)
from urban_hs.core.logger import (
    correlation_context,
    get_correlation_id,
    get_logger,
    get_module_logger,
    set_correlation_id,
    setup_logging,
    trace,
)
from urban_hs.core.memory import (
    AllocationRecord,
    JSONLStreamingParser,
    LeakReport,
    MemoryProfiler,
    MemorySnapshot,
    StreamingParser,
    abatch,
    afilter,
    alimit,
    amap,
    detect_gc_leaks,
    memory_profile,
    stream_parse_jsonl,
    stream_parse_pcap,
)
from urban_hs.core.plugins import (
    PluginInstance,
    PluginManager,
    PluginMetadata,
    PluginStatus,
    PluginType,
    UrbanPlugin,
    create_plugin_manager,
    urban_plugin,
)
from urban_hs.core.process_mgr import (
    ProcessCallback,
    ProcessContext,
    ProcessLimits,
    ProcessManager,
    ProcessResult,
    StreamCallback,
    get_process_manager,
    init_process_manager,
    shutdown_process_manager,
)
from urban_hs.core.scheduler import (
    JobStatus,
    ScheduledJob,
    Scheduler,
    TriggerType,
)
from urban_hs.core.security import (
    MODULE_CAPABILITIES,
    SECCOMP_PROFILES,
    Capability,
    CapabilitySet,
    RootlessChroot,
    RootlessChrootConfig,
    SeccompAction,
    SeccompFilter,
    SeccompProfile,
    SeccompRule,
    SupplyChainConfig,
    SupplyChainVerifier,
    drop_privileges,
    harden_process,
)
from urban_hs.core.storage import Storage, get_storage, init_storage, shutdown_storage

__all__ = [
    # Config
    "Config",
    "get_config",
    "init_config",
    "shutdown_config",
    
    # Event Bus
    "Event",
    "EventBus",
    "EventHandler",
    "EventPriority",
    "DeadLetterQueue",
    "get_event_bus",
    "init_event_bus",
    "shutdown_event_bus",
    
    # Logger
    "get_logger",
    "get_module_logger",
    "setup_logging",
    "correlation_context",
    "set_correlation_id",
    "get_correlation_id",
    "trace",
    
    # Storage
    "Storage",
    "get_storage",
    "init_storage",
    "shutdown_storage",
    
    # Process Manager
    "ProcessManager",
    "ProcessLimits",
    "ProcessResult",
    "ProcessContext",
    "ProcessCallback",
    "StreamCallback",
    "get_process_manager",
    "init_process_manager",
    "shutdown_process_manager",
    
    # Health
    "HealthStatus",
    "HealthCheckResult",
    "SystemMetrics",
    "HealthChecker",
    "HealthCheckMiddleware",
    "create_health_checker",
    
    # Scheduler
    "TriggerType",
    "JobStatus",
    "ScheduledJob",
    "Scheduler",
    
    # Concurrency
    "ResourceType",
    "ResourcePriority",
    "ResourceConfig",
    "ResourceUsage",
    "ResourcePool",
    "ResourceManager",
    "get_resource_manager",
    
    # Memory
    "MemorySnapshot",
    "AllocationRecord",
    "LeakReport",
    "MemoryProfiler",
    "memory_profile",
    "detect_gc_leaks",
    "StreamingParser",
    "JSONLStreamingParser",
    "stream_parse_jsonl",
    "stream_parse_pcap",
    "abatch",
    "alimit",
    "afilter",
    "amap",
    
    # Security
    "Capability",
    "CapabilitySet",
    "MODULE_CAPABILITIES",
    "drop_privileges",
    "SeccompAction",
    "SeccompRule",
    "SeccompProfile",
    "SeccompFilter",
    "SECCOMP_PROFILES",
    "RootlessChrootConfig",
    "RootlessChroot",
    "SupplyChainConfig",
    "SupplyChainVerifier",
    "harden_process",
    
    # Plugins
    "PluginStatus",
    "PluginType",
    "PluginMetadata",
    "PluginInstance",
    "UrbanPlugin",
    "PluginManager",
    "create_plugin_manager",
    "urban_plugin",
]


# Convenience function for bootstrapping
async def init_core(
    config_file: Optional[str] = None,
    log_level: str = "INFO",
    jsonl_dir: Optional[str] = None,
    sqlite_path: Optional[str] = None,
    redis_url: Optional[str] = None,
    **kwargs,
) -> Dict[str, Any]:
    """
    Initialize all core services.
    
    Returns dict with initialized services.
    """
    import os
    from pathlib import Path
    
    # Initialize config first to get paths
    config = await init_config(config_file=config_file)
    
    # Resolve paths from config
    if jsonl_dir is None:
        jsonl_dir = config.storage.resolve_jsonl_dir()
    if sqlite_path is None:
        sqlite_path = config.storage.resolve_sqlite_path()
    if redis_url is None:
        redis_url = config.storage.redis_url
    
    # Ensure directories exist
    Path(config.storage.data_root).mkdir(parents=True, exist_ok=True)
    Path(jsonl_dir).mkdir(parents=True, exist_ok=True)
    Path(config.storage.log_root).mkdir(parents=True, exist_ok=True)
    Path(config.storage.resolve_hashes_dir()).mkdir(parents=True, exist_ok=True)
    Path(config.storage.resolve_pcaps_dir()).mkdir(parents=True, exist_ok=True)
    
    # Setup logging first
    setup_logging(level=log_level, jsonl_dir=jsonl_dir)
    
    logger = get_logger("core.init")
    logger.info("Initializing core services")
    
    # Initialize services
    bus = await init_event_bus()
    storage = await init_storage(
        sqlite_path=sqlite_path,
        redis_url=redis_url,
    )
    pm = await init_process_manager()
    
    logger.info("Core services initialized", services=["event_bus", "config", "storage", "process_manager"])
    
    return {
        "event_bus": bus,
        "config": config,
        "storage": storage,
        "process_manager": pm,
    }


async def shutdown_core() -> None:
    """Shutdown all core services gracefully."""
    logger = get_logger("core.shutdown")
    logger.info("Shutting down core services")
    
    await shutdown_process_manager()
    await shutdown_storage()
    await shutdown_config()
    await shutdown_event_bus()
    
    logger.info("Core services shut down")