"""
Log rotation + PII-safe formatters for Sprint 8A.

Provides:
- RotatingFileHandler wrapper with size + age limits
- PII filter that redacts MAC addresses from logs
- Separate audit log and operational log configs
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
from pathlib import Path
from typing import Optional

from urban_hs.core.mac_anonymiser import redact_text


class PIIFormatter(logging.Formatter):
    """Formatter that redacts MAC addresses from log records."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return redact_text(message)


class SensitiveFilter(logging.Filter):
    """Reject records from sensitive logger names."""

    SENSITIVE_PREFIXES = ("urban_hs.core.secrets", "urban_hs.core.auth")

    def filter(self, record: logging.LogRecord) -> bool:
        for prefix in self.SENSITIVE_PREFIXES:
            if record.name.startswith(prefix):
                return False
        return True


def build_rotating_handler(
    path: str,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
    encoding: str = "utf-8",
) -> RotatingFileHandler:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        filename=path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding=encoding,
    )
    handler.setFormatter(PIIFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(SensitiveFilter())
    return handler


def build_time_rotating_handler(
    path: str,
    when: str = "midnight",
    backup_count: int = 14,
    encoding: str = "utf-8",
) -> TimedRotatingFileHandler:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    handler = TimedRotatingFileHandler(
        filename=path,
        when=when,
        backupCount=backup_count,
        encoding=encoding,
    )
    handler.setFormatter(PIIFormatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    handler.addFilter(SensitiveFilter())
    return handler


def configure_logging(
    base_dir: str = "/var/log/urban-hs",
    level: int = logging.INFO,
    audit_level: int = logging.INFO,
) -> None:
    """Configure application-wide logging with rotation + PII filtering."""
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        operational = build_rotating_handler(os.path.join(base_dir, "urban-hs.log"))
        operational.setLevel(level)
        root.addHandler(operational)

    audit_logger = logging.getLogger("urban_hs.audit")
    audit_logger.propagate = False
    audit = build_time_rotating_handler(os.path.join(base_dir, "audit.log"))
    audit.setLevel(audit_level)
    audit_logger.addHandler(audit)
