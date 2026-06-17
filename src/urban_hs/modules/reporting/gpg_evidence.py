"""
GPG Evidence Signing - Chain of custody and evidence integrity.

Provides GPG signing for all captured artifacts with:
- Detached signatures for each artifact
- Evidence log with append-only integrity
- Chain of custody documentation
- Verification utilities
"""

import asyncio
import hashlib
import json
import os
import structlog
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union, Tuple
from uuid import uuid4

try:
    import gnupg as gpg_module
    GPG_AVAILABLE = True
except ImportError:
    gpg_module = None
    GPG_AVAILABLE = False

gpg = gpg_module

logger = structlog.get_logger(__name__)


class SignatureFormat(Enum):
    """Signature format."""
    DETACHED_ASCII = "detached_ascii"      # .asc file
    DETACHED_BINARY = "detached_binary"    # .sig file
    CLEAR_SIGNED = "clear_signed"          # inline signature


@dataclass
class EvidenceRecord:
    """Single evidence entry in the chain of custody log."""
    id: str = field(default_factory=lambda: str(uuid4()))
    artifact_path: str = ""
    artifact_hash_sha256: str = ""
    artifact_hash_blake2b: str = ""
    signature_path: str = ""
    signature_format: SignatureFormat = SignatureFormat.DETACHED_ASCII
    signed_at: datetime = field(default_factory=datetime.utcnow)
    signed_by_key_id: str = ""
    collector: str = ""
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    previous_entry_hash: str = ""  # For chaining
    
    def compute_chain_hash(self) -> str:
        """Compute hash of this entry for chain integrity."""
        data = f"{self.id}{self.artifact_path}{self.artifact_hash_sha256}{self.previous_entry_hash}{self.signed_at.isoformat()}"
        return hashlib.sha256(data.encode()).hexdigest()


@dataclass
class ChainOfCustody:
    """Complete chain of custody for a session."""
    id: str = field(default_factory=lambda: str(uuid4()))
    session_id: str = ""
    entries: List[Dict[str, Any]] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    last_entry_hash: str = ""
    gpg_key_id: str = ""
    gpg_fingerprint: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_entry(self, entry: EvidenceRecord):
        """Add entry to chain."""
        entry_data = {
            "id": entry.id,
            "artifact_path": entry.artifact_path,
            "artifact_hash_sha256": entry.artifact_hash_sha256,
            "artifact_hash_blake2b": entry.artifact_hash_blake2b,
            "signature_path": entry.signature_path,
            "signature_format": entry.signature_format.value,
            "signed_at": entry.signed_at.isoformat(),
            "signed_by_key_id": entry.signed_by_key_id,
            "collector": entry.collector,
            "description": entry.description,
            "metadata": entry.metadata,
            "previous_entry_hash": self.last_entry_hash,
        }
        
        # Compute chain hash
        entry_dict = {
            "id": entry.id,
            "artifact_path": entry.artifact_path,
            "artifact_hash_sha256": entry.artifact_hash_sha256,
            "artifact_hash_blake2b": entry.artifact_hash_blake2b,
            "signature_path": entry.signature_path,
            "signature_format": entry.signature_format.value,
            "signed_at": entry.signed_at.isoformat(),
            "signed_by_key_id": entry.signed_by_key_id,
            "collector": entry.collector,
            "description": entry.description,
            "metadata": entry.metadata,
            "previous_entry_hash": self.last_entry_hash,
        }
        
        # Compute chain hash
        entry_data = f"{entry.id}{entry.artifact_path}{entry.artifact_hash_sha256}{self.last_entry_hash}{entry.signed_at.isoformat()}"
        chain_hash = hashlib.sha256(entry_data.encode()).hexdigest()
        entry_dict["chain_hash"] = chain_hash
        
        self.entries.append(entry_dict)
        self.last_entry_hash = chain_hash
    
    def verify_chain(self) -> Tuple[bool, List[str]]:
        """Verify entire chain integrity. Returns (is_valid, error_messages)."""
        errors = []
        expected_prev = ""
        
        for i, entry in enumerate(self.entries):
            # Verify chain linkage
            if entry["previous_entry_hash"] != expected_prev:
                errors.append(f"Entry {i}: Chain broken - previous hash mismatch")
            
            # Verify entry hash
            entry_data = f"{entry['id']}{entry['artifact_path']}{entry['artifact_hash_sha256']}{entry['previous_entry_hash']}{entry['signed_at']}"
            computed_hash = hashlib.sha256(entry_data.encode()).hexdigest()
            if computed_hash != entry.get("chain_hash", ""):
                errors.append(f"Entry {i}: Chain hash mismatch")
            
            expected_prev = entry.get("chain_hash", "")
        
        return len(errors) == 0, errors


class GPGSigner:
    """
    GPG signing for evidence and artifacts.
    
    Features:
    - Detached signatures (ASCII armor)
    - Batch signing
    - Key management
    - Verification
    - Export/import
    """
    
    def __init__(
        self,
        gpg_home: Optional[str] = None,
        key_id: Optional[str] = None,
        passphrase: Optional[str] = None,
        gpg_binary: str = "gpg",
    ):
        if not GPG_AVAILABLE:
            raise RuntimeError("gnupg not available. Install with: pip install gnupg")
        
        self.gpg_home = gpg_home
        self.key_id = key_id
        self.passphrase = passphrase
        self.gpg_binary = gpg_binary
        
        # Initialize GPG
        assert gpg_module is not None  # GPG_AVAILABLE check above guarantees this
        self.gpg = gpg_module.GPG(
            gpgbinary=gpg_binary,
            gnupghome=gpg_home,
            verbose=False,
        )
        
        # Set default key if provided
        if key_id:
            self._verify_key(key_id)
    
    def _verify_key(self, key_id: str) -> bool:
        """Verify key exists and is usable."""
        keys = self.gpg.list_keys(secret=True)
        for key in keys:
            if key_id in key.get('keyid', '') or key_id in key.get('fingerprint', ''):
                return True
        logger.warning("Key not found in secret keyring", key_id=key_id)
        return False
    
    def sign_file(
        self,
        file_path: str,
        output_path: Optional[str] = None,
        format: SignatureFormat = SignatureFormat.DETACHED_ASCII,
        key_id: Optional[str] = None,
    ) -> bool:
        """
        Sign a file with GPG.
        
        Args:
            file_path: Path to file to sign
            output_path: Output path (optional, auto-generated)
            format: Signature format
            key_id: Key ID to use (overrides default)
        
        Returns:
            True if successful
        """
        if not os.path.exists(file_path):
            logger.error("File not found", path=file_path)
            return False
        
        key_id = key_id or self.key_id
        if not key_id:
            logger.error("No GPG key ID specified")
            return False
        
        # Generate output path if not provided
        if output_path is None:
            if format == SignatureFormat.DETACHED_ASCII:
                output_path = file_path + ".asc"
            elif format == SignatureFormat.DETACHED_BINARY:
                output_path = file_path + ".sig"
            else:
                output_path = file_path + ".asc"
        
        # Ensure output directory exists
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        
        try:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            
            if format == SignatureFormat.DETACHED_ASCII:
                signature = self.gpg.sign(
                    file_data,
                    keyid=key_id,
                    passphrase=self.passphrase,
                    detach=True,
                    armor=True,
                )
            elif format == SignatureFormat.DETACHED_BINARY:
                signature = self.gpg.sign(
                    file_data,
                    keyid=key_id,
                    passphrase=self.passphrase,
                    detach=True,
                    armor=False,
                )
            else:  # CLEAR_SIGNED
                signature = self.gpg.sign(
                    file_data,
                    keyid=key_id,
                    passphrase=self.passphrase,
                    detach=False,
                    armor=True,
                )
            
            if signature:
                with open(output_path, 'w' if format == SignatureFormat.DETACHED_ASCII else 'wb') as f:
                    f.write(str(signature))
                
                logger.info("File signed", input=file_path, output=output_path, format=format.value)
                return True
            else:
                logger.error("Signing failed", status=self.gpg.last_status)
                return False
                
        except Exception as e:
            logger.error("Signing error", file=file_path, error=str(e))
            return False
    
    def sign_batch(
        self,
        files: List[str],
        output_dir: Optional[str] = None,
        format: SignatureFormat = SignatureFormat.DETACHED_ASCII,
        key_id: Optional[str] = None,
    ) -> Dict[str, bool]:
        """Sign multiple files."""
        results = {}
        
        for file_path in files:
            if output_dir:
                output_path = os.path.join(output_dir, os.path.basename(file_path) + ".asc")
            else:
                output_path = None
            
            results[file_path] = self.sign_file(file_path, output_path, format, key_id)
        
        return results
    
    def verify_signature(
        self,
        file_path: str,
        signature_path: str,
    ) -> Dict[str, Any]:
        """
        Verify a detached signature.
        
        Returns:
            Dict with verification result
        """
        if not os.path.exists(file_path):
            return {"valid": False, "error": "File not found"}
        
        if not os.path.exists(signature_path):
            return {"valid": False, "error": "Signature file not found"}
        
        try:
            with open(signature_path, 'r') as f:
                signature_data = f.read()
            
            verified = self.gpg.verify(
                signature_path,
                file_path,
            )
            
            result = {
                "valid": verified.valid,
                "key_id": verified.key_id,
                "fingerprint": verified.fingerprint,
                "username": verified.username,
                "timestamp": verified.timestamp,
                "expire_timestamp": verified.expire_timestamp,
            }
            
            return result
            
        except Exception as e:
            logger.error("Verification error", error=str(e))
            return {"valid": False, "error": str(e)}
    
    def get_key_info(self, key_id: Optional[str] = None) -> Dict[str, Any]:
        """Get key information."""
        key_id = key_id or self.key_id
        
        keys = self.gpg.list_keys(secret=True)
        for key in keys:
            if key_id in key.get('keyid', '') or key_id in key.get('fingerprint', ''):
                return {
                    "keyid": key.get('keyid'),
                    "fingerprint": key.get('fingerprint'),
                    "uids": key.get('uids', []),
                    "trust": key.get('trust', ''),
                    "length": key.get('length'),
                    "algo": key.get('algo'),
                    "date": key.get('date'),
                    "expires": key.get('expires'),
                }
        
        return {}


class EvidenceLogger:
    """
    Maintains append-only evidence log with GPG signatures.
    
    Creates:
    - evidence_log.json: Append-only JSON log
    - evidence_log.json.asc: GPG signature
    - Individual artifact signatures
    """
    
    def __init__(
        self,
        log_dir: str = "/var/lib/urban-hs/evidence",
        gpg_signer: Optional[GPGSigner] = None,
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        
        self.log_file = self.log_dir / "evidence_log.json"
        self.gpg_signer = gpg_signer
        
        # Initialize log if not exists
        if not self.log_file.exists():
            self._init_log()
    
    def _init_log(self):
        """Initialize empty evidence log."""
        initial = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "entries": [],
        }
        with open(self.log_file, 'w') as f:
            json.dump(initial, f, indent=2)
        
        # Sign initial log
        self._sign_log()
    
    def _sign_log(self):
        """Sign the log file with GPG."""
        if self.gpg_signer:
            self.gpg_signer.sign_file(
                str(self.log_file),
                format=SignatureFormat.DETACHED_ASCII,
            )
    
    def add_entry(
        self,
        artifact_path: str,
        description: str = "",
        collector: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Add evidence entry to log."""
        # Compute hashes
        sha256_hash = self._compute_hash(artifact_path, "sha256")
        blake2b_hash = self._compute_hash(artifact_path, "blake2b")
        
        entry = {
            "id": str(uuid4()),
            "artifact_path": artifact_path,
            "artifact_hash_sha256": sha256_hash,
            "artifact_hash_blake2b": blake2b_hash,
            "description": description,
            "collector": collector,
            "metadata": metadata or {},
            "timestamp": datetime.utcnow().isoformat(),
            "entry_hash": "",
        }
        
        # Compute entry hash (includes all fields except entry_hash itself)
        entry_copy = {k: v for k, v in entry.items() if k != "entry_hash"}
        entry["entry_hash"] = self._compute_entry_hash(entry_copy)
        
        # Append to log
        with open(self.log_file, 'r') as f:
            log_data = json.load(f)
        
        log_data["entries"].append(entry)
        log_data["last_updated"] = datetime.utcnow().isoformat()
        
        with open(self.log_file, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        # Re-sign log
        self._sign_log()
        
        return entry
    
    def _compute_hash(self, file_path: str, algorithm: str = "sha256") -> str:
        """Compute file hash."""
        if algorithm == "sha256":
            h = hashlib.sha256()
        elif algorithm == "blake2b":
            h = hashlib.blake2b()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        
        return h.hexdigest()
    
    def _compute_entry_hash(self, entry: Dict[str, Any]) -> str:
        """Compute hash of log entry for tamper evidence."""
        # Serialize without entry_hash
        data = json.dumps(entry, sort_keys=True, default=str)
        return hashlib.sha256(data.encode()).hexdigest()
    
    def verify_log(self) -> Tuple[bool, List[str]]:
        """Verify log integrity."""
        errors = []
        
        # Verify GPG signature
        if self.gpg_signer:
            sig_file = str(self.log_file) + ".asc"
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    sig_data = f.read()
                verified = self.gpg_signer.gpg.verify(sig_data, str(self.log_file))
                if not verified.valid:
                    errors.append("GPG signature invalid or missing")
            else:
                errors.append("GPG signature file missing")
        
        # Verify entry hashes
        with open(self.log_file, 'r') as f:
            log_data = json.load(f)
        
        for i, entry in enumerate(log_data.get("entries", [])):
            entry_hash = entry.pop("entry_hash", "")
            computed = self._compute_entry_hash(entry)
            entry["entry_hash"] = entry_hash  # Restore
            
            if entry_hash != self._compute_entry_hash(entry):
                errors.append(f"Entry {entry.get('id', i)} hash mismatch")
        
        return len(errors) == 0, errors
    
    def get_entries(self) -> List[Dict[str, Any]]:
        """Get all log entries."""
        with open(self.log_file, 'r') as f:
            log_data = json.load(f)
        return log_data.get("entries", [])


class ChainOfCustodyManager:
    """
    High-level chain of custody management.
    
    Coordinates:
    - GPG signing
    - Evidence logging
    - Chain of custody documentation
    - Verification and reporting
    """
    
    def __init__(
        self,
        session_id: str,
        base_dir: str = "/var/lib/urban-hs/evidence",
        gpg_signer: Optional[GPGSigner] = None,
    ):
        self.session_id = session_id
        self.base_dir = Path(base_dir) / session_id
        self.base_dir.mkdir(parents=True, exist_ok=True)
        
        self.gpg_signer = gpg_signer or GPGSigner()
        self.evidence_log = EvidenceLogger(
            log_dir=str(self.base_dir),
            gpg_signer=self.gpg_signer,
        )
        self.custody_chain = ChainOfCustody(
            session_id=session_id,
            gpg_key_id=self.gpg_signer.key_id if self.gpg_signer else "",
        )
    
    def add_artifact(
        self,
        artifact_path: str,
        description: str = "",
        collector: str = "",
        metadata: Optional[Dict[str, Any]] = None,
        sign: bool = True,
    ) -> Dict[str, Any]:
        """Add artifact to chain of custody."""
        # Add to evidence log
        entry = self.evidence_log.add_entry(
            artifact_path=artifact_path,
            description=description,
            collector=collector,
            metadata=metadata,
        )
        
        # Create evidence record
        evidence_record = EvidenceRecord(
            artifact_path=artifact_path,
            artifact_hash_sha256=entry["artifact_hash_sha256"],
            artifact_hash_blake2b=entry["artifact_hash_blake2b"],
            description=description,
            collector=collector,
            metadata=metadata or {},
        )
        
        if self.gpg_signer and sign:
            sig_path = artifact_path + ".asc"
            self.gpg_signer.sign_file(artifact_path, sig_path)
            evidence_record.signature_path = sig_path
            evidence_record.signed_by_key_id = self.gpg_signer.key_id or ""
        
        # Add to chain
        self.custody_chain.add_entry(evidence_record)
        
        return {
            "entry": entry,
            "evidence_record": evidence_record,
            "chain_valid": True,
        }
    
    def verify_custody_chain(self) -> Tuple[bool, List[str]]:
        """Verify entire chain of custody."""
        errors = []
        
        # Verify evidence log
        log_valid, log_errors = self.evidence_log.verify_log()
        if not log_valid:
            errors.extend(log_errors)
        
        # Verify custody chain
        chain_valid, chain_errors = self.custody_chain.verify_chain()
        if not chain_valid:
            errors.extend(chain_errors)
        
        # Verify individual artifact signatures
        for entry in self.custody_chain.entries:
            if entry.get("signature_path"):
                artifact_path = entry["artifact_path"]
                sig_path = entry["signature_path"]
                
                if os.path.exists(artifact_path) and os.path.exists(sig_path):
                    if self.gpg_signer:
                        verified = self.gpg_signer.gpg.verify(sig_path, artifact_path)
                        if not verified.valid:
                            errors.append(f"Signature invalid for {artifact_path}")
        
        return len(errors) == 0, errors
    
    def generate_report(self, output_path: str) -> bool:
        """Generate chain of custody report."""
        try:
            report = {
                "session_id": self.custody_chain.session_id,
                "created_at": self.custody_chain.created_at.isoformat(),
                "gpg_key_id": self.custody_chain.gpg_key_id,
                "gpg_fingerprint": self.custody_chain.gpg_fingerprint,
                "total_artifacts": len(self.custody_chain.entries),
                "entries": self.custody_chain.entries,
            }
            
            with open(output_path, 'w') as f:
                json.dump(report, f, indent=2, default=str)
            
            return True
        except Exception as e:
            logger.error("Report generation failed", error=str(e))
            return False


# Utility functions
def create_gpg_key(
    name: str,
    email: str,
    passphrase: Optional[str] = None,
    key_type: str = "RSA",
    key_length: int = 4096,
    gpg_home: Optional[str] = None,
    gpg_binary: str = "gpg",
) -> str:
    """Create a new GPG key for evidence signing."""
    import gnupg
    
    gpg_obj = gnupg.GPG(
        gpgbinary=gpg_binary,
        gnupghome=gpg_home,
    )
    
    input_data = gpg_obj.gen_key_input(
        name_real=name,
        name_email=email,
        passphrase=passphrase,
        key_type=key_type,
        key_length=key_length,
    )
    
    key = gpg_obj.gen_key(input_data)
    return key.fingerprint


def verify_gpg_signature(
    file_path: str,
    signature_path: str,
    gpg_home: Optional[str] = None,
    gpg_binary: str = "gpg",
) -> Dict[str, Any]:
    """Verify a GPG signature."""
    import gnupg
    
    gpg = gnupg.GPG(
        gpgbinary=gpg_binary,
        gnupghome=gpg_home,
    )
    
    with open(signature_path, 'r') as f:
        signature_data = f.read()
    
    verified = gpg.verify(signature_path, file_path)
    
    return {
        "valid": verified.valid,
        "key_id": verified.key_id,
        "fingerprint": verified.fingerprint,
        "username": verified.username,
        "timestamp": verified.timestamp,
        "expire_timestamp": verified.expire_timestamp,
    }


# Export all public classes
__all__ = [
    "SignatureFormat",
    "EvidenceRecord",
    "ChainOfCustody",
    "GPGSigner",
    "EvidenceLogger",
    "ChainOfCustodyManager",
    "create_gpg_key",
    "verify_gpg_signature",
]