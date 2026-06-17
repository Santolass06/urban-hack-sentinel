"""
Core package - Shared infrastructure for Urban Hack Sentinel.
"""

import asyncio
from typing import Dict, Any, Optional

from urban_hs.core.config import Config, get_config, init_config, shutdown_config
from urban_hs.core.event_bus import (
    Event,
    EventBus,
    EventHandler,
    EventPriority,
    get_event_bus,
    init_event_bus,
    shutdown_event_bus,
)
from urban_hs.core.event_bus import DeadLetterQueue
from urban_hs.core.logger import (
    get_logger,
    get_module_logger,
    setup_logging,
    correlation_context,
    set_correlation_id,
    get_correlation_id,
    trace,
)
from urban_hs.core.storage import Storage, get_storage, init_storage, shutdown_storage
from urban_hs.core.process_mgr import (
    ProcessManager,
    ProcessManager,
    ProcessLimits,
    ProcessResult,
    ProcessContext,
    ProcessCallback,
    StreamCallback,
    get_process_manager,
    init_process_manager,
    shutdown_process_manager,
)

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
]


# Convenience function for bootstrapping
async def init_core(
    config_file: Optional[str] = None,
    log_level: str = "INFO",
    jsonl_dir: str = "/var/log/urban-hs/jsonl",
    sqlite_path: str = "/var/lib/urban-hs/urban.db",
    redis_url: str = "redis://localhost:6379/0",
    **kwargs,
) -> Dict[str, Any]:
    """
    Initialize all core services.
    
    Returns dict with initialized services.
    """
    import os
    from pathlib import Path
    
    # Ensure directories exist
    Path("/var/lib/urban-hs").mkdir(parents=True, exist_ok=True)
    Path("/var/log/urban-hs/jsonl").mkdir(parents=True, exist_ok=True)
    Path("/var/log/urban-hs").mkdir(parents=True, exist_ok=True)
    Path("/var/lib/urban-hs/hashes").mkdir(parents=True, exist_ok=True)
    Path("/var/lib/urban-hs/pcaps").mkdir(parents=True, exist_ok=True)
    
    # Setup logging first
    setup_logging(level=log_level, jsonl_dir="/var/log/urban-hs/jsonl")
    
    logger = get_logger("core.init")
    logger.info("Initializing core services")
    
    # Initialize services
    bus = await init_event_bus()
    config = await init_config(config_file=config_file)
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