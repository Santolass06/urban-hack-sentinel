"""
Structured Logging - JSONL + Rich console output with correlation IDs.

Provides:
- Structured logging with structlog
- JSONL output for machine parsing
- Rich console for human-readable output
- Correlation ID tracking across async boundaries
- Log levels and filtering
"""

import logging
import os
import sys
from contextvars import ContextVar
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

import structlog
from structlog.types import EventDict, WrappedLogger

# Context variable for correlation ID
_correlation_id: ContextVar[Optional[str]] = ContextVar("correlation_id", default=None)

# Custom log levels
TRACE_LEVEL = 5
logging.addLevelName(TRACE_LEVEL, "TRACE")


def add_correlation_id(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Add correlation ID from context variable."""
    cid = _correlation_id.get()
    if cid:
        event_dict["correlation_id"] = cid
    return event_dict


def add_timestamp(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Add ISO timestamp."""
    event_dict["timestamp"] = datetime.utcnow().isoformat() + "Z"
    return event_dict


def add_level(logger: WrappedLogger, method_name: str, event_dict: EventDict) -> EventDict:
    """Ensure level is present."""
    event_dict["level"] = method_name.upper()
    return event_dict


def setup_logging(
    level: str = "INFO",
    jsonl_dir: Optional[str] = None,
    console: bool = True,
    console_format: str = "rich",
) -> None:
    """
    Configure structured logging.
    
    Args:
        level: Log level (TRACE, DEBUG, INFO, WARNING, ERROR, CRITICAL)
        jsonl_dir: Directory for JSONL logs (per-module files). Defaults to Config.storage.jsonl_dir.
        console: Enable console output
        console_format: "rich" for Rich formatting, "json" for JSON lines
    """
    if jsonl_dir is None:
        from urban_hs.core.config import get_config
        jsonl_dir = get_config().storage.resolve_jsonl_dir()
    # Parse level
    log_level = getattr(logging, level.upper(), logging.INFO)
    if level.upper() == "TRACE":
        log_level = TRACE_LEVEL

    # JSONL file logging
    jsonl_logger = None
    if jsonl_dir:
        log_dir = Path(jsonl_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
        
        class JSONLFileLogger:
            def __init__(self, log_dir: Path):
                self.log_dir = log_dir
                self._files: Dict[str, Any] = {}
            
            def _get_file(self, module: str) -> Any:
                if module not in self._files:
                    file_path = self.log_dir / f"{module}.jsonl"
                    self._files[module] = open(file_path, "a", buffering=1)
                return self._files[module]
            
            def __call__(self, logger: Any, method_name: str, event_dict: EventDict) -> None:
                module = event_dict.get("module", "root")
                file = self._get_file(module)
                file.write(structlog.processors.JSONRenderer()(None, None, event_dict) + "\n")
                file.flush()
            
            def close(self) -> None:
                for f in self._files.values():
                    f.close()
                self._files.clear()
        
        jsonl_logger = JSONLFileLogger(Path(jsonl_dir))

    # Configure structlog
    processors = [
        structlog.contextvars.merge_contextvars,
        add_correlation_id,
        add_timestamp,
        add_level,
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
    ]

    if jsonl_logger:
        processors.append(jsonl_logger)

    # Console output
    if console:
        if console_format == "rich":
            processors.append(structlog.processors.JSONRenderer())
        else:
            processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(log_level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stdout),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging to route through structlog
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )


def get_logger(name: str = None) -> structlog.BoundLogger:
    """Get a structured logger for a module."""
    return structlog.get_logger(name)


def set_correlation_id(cid: str) -> None:
    """Set correlation ID for current context."""
    _correlation_id.set(cid)


def get_correlation_id() -> Optional[str]:
    """Get current correlation ID."""
    return _correlation_id.get()


def clear_correlation_id() -> None:
    """Clear correlation ID."""
    _correlation_id.set(None)


# Context manager for correlation ID
class correlation_context:
    """Context manager for setting correlation ID."""
    
    def __init__(self, cid: Optional[str] = None):
        self.cid = cid or f"req-{os.urandom(8).hex()}"
        self._token = None
    
    def __enter__(self) -> str:
        self._token = _correlation_id.set(self.cid)
        return self.cid
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        _correlation_id.reset(self._token)


def trace(logger: structlog.BoundLogger, msg: str, **kwargs: Any) -> None:
    """Log at TRACE level."""
    logger._proxy_to_logger("log", TRACE_LEVEL, msg, **kwargs)


# Convenience functions
def get_module_logger(module_name: str) -> structlog.BoundLogger:
    """Get logger for a specific module."""
    return structlog.get_logger(module_name)