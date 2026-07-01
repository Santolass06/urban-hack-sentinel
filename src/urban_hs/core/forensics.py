"""
Forensics and evidence integrity for Urban Hack Sentinel.

Design:
- Reuse the existing GPG/evidence implementation in
  ``urban_hs.modules.reporting.gpg_evidence``.
- Add 8B-specific behaviour here: retention policy, MAC anonymisation
  hooks, and CLI-oriented helpers for verify/seal/audit-trail.
"""

from __future__ import annotations

import json
import os
import structlog
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

logger = structlog.get_logger(__name__)

if TYPE_CHECKING:
    from urban_hs.modules.reporting.gpg_evidence import (
        EvidenceLogger as EvidenceLogger,
        GPGSigner as GPGSigner,
    )

try:
    from urban_hs.modules.reporting.gpg_evidence import (
        EvidenceLogger,
        GPGSigner,
    )

    REPORTING_EVIDENCE_AVAILABLE = True
except ImportError:  # pragma: no cover - optional dependency path
    REPORTING_EVIDENCE_AVAILABLE = False
    EvidenceLogger = None  # type: ignore[assignment,misc]
    GPGSigner = None  # type: ignore[assignment,misc]


@dataclass
class RetentionPolicy:
    """Time-to-live and erasure rules for sessions/artifacts."""

    default_ttl_days: int = 30
    grace_days: int = 7
    base_dir: str = "/var/lib/urban-hs/artifacts"

    def expired(self, updated_at: Optional[str]) -> bool:
        if not updated_at:
            return True
        try:
            dt = datetime.fromisoformat(updated_at)
            age = (datetime.now(timezone.utc) - dt).total_seconds() / 86400
            return age > (self.default_ttl_days + self.grace_days)
        except Exception:
            return True


@dataclass
class EvidenceBundle:
    """Session evidence collection with anonymisation and retention metadata."""

    session_id: str
    base_dir: str = ""
    retention: RetentionPolicy = field(default_factory=RetentionPolicy)
    records: List[Dict[str, Any]] = field(default_factory=list)
    custody_entries: List[Dict[str, Any]] = field(default_factory=list)
    gpg_signer: Optional[GPGSigner] = None
    evidence_logger: Optional[EvidenceLogger] = None

    def add(self, path: str) -> Dict[str, Any]:
        abs_path = str(Path(path).resolve())
        if not os.path.exists(abs_path):
            raise FileNotFoundError(abs_path)

        size = os.path.getsize(abs_path)
        sha256 = self._sha256(abs_path)
        blake2b = self._blake2b(abs_path)
        created_at = datetime.now(timezone.utc).isoformat()

        record = {
            "path": abs_path,
            "sha256": sha256,
            "blake2b": blake2b,
            "gpg_sig": None,
            "size_bytes": size,
            "created_at": created_at,
            "session_id": self.session_id,
        }

        if self.gpg_signer is not None:
            try:
                sig_path = self.gpg_signer.sign_file(abs_path)
                if sig_path:
                    record["gpg_sig"] = sig_path
            except Exception as exc:
                logger.warning("GPG sign failed", path=abs_path, error=str(exc))

        self.records.append(record)
        self._append_custody("add", abs_path, record)
        return record

    def index_path(self) -> str:
        base = Path(self.base_dir) if self.base_dir else Path(
            self.records[0]["path"] if self.records else "."
        ).resolve().parent
        return str(base / f"{self.session_id}-evidence-index.json")

    def write_index(self, path: Optional[str] = None) -> str:
        target = path or self.index_path()
        payload = {
            "session_id": self.session_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "artifacts": self.records,
            "custody": self.custody_entries,
        }
        Path(target).write_text(
            json.dumps(payload, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        return target

    def _append_custody(self, action: str, path: str, meta: Dict[str, Any]) -> None:
        self.custody_entries.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "action": action,
                "path": path,
                "meta": meta,
            }
        )

    @staticmethod
    def _sha256(path: str) -> str:
        import hashlib

        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def _blake2b(path: str) -> str:
        import hashlib

        h = hashlib.blake2b(digest_size=32)
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
