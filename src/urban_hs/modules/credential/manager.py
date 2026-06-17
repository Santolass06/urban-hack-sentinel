"""
Credential Manager - Normalization, deduplication, Hashcat integration.

Handles credentials from various sources:
- WiFi handshake cracking
- WPS PIN recovery
- Network service brute force
- Default credential discovery
- Metasploit session credentials
- Web application credentials
"""

import asyncio
import hashlib
import json
import os
import re
import structlog
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union, Set
from uuid import uuid4

logger = structlog.get_logger(__name__)


class CredentialType(Enum):
    """Type of credential."""
    PLAINTEXT = "plaintext"           # Username:password
    HASH = "hash"                     # Hash only (NTLM, MD5, etc.)
    WPA_HANDSHAKE = "wpa_handshake"   # WPA/WPA2 handshake
    WPA_PMKID = "wpa_pmkid"           # WPA3 PMKID
    WPS_PIN = "wps_pin"               # WPS PIN
    SSH_KEY = "ssh_key"               # SSH private key
    API_KEY = "api_key"               # API key/token
    CERTIFICATE = "certificate"       # SSL/TLS certificate
    COOKIE = "cookie"                 # Session cookie
    TOKEN = "token"                   # OAuth/JWT token


class CredentialSource(Enum):
    """Source of credential."""
    WIFI_CRACK = "wifi_crack"           # Handshake/PMKID cracking
    WPS_ATTACK = "wps_attack"           # WPS PIN/brute force
    SERVICE_BRUTE = "service_brute"     # SSH, FTP, HTTP, etc. brute force
    DEFAULT_CREDS = "default_creds"     # Default credential lists
    EXPLOIT = "exploit"                 # Post-exploitation gathering
    METASPLOIT = "metasploit"           # Metasploit session dumping
    WEB_APP = "web_app"                 # Web application login
    CONFIG_DUMP = "config_dump"         # Configuration file extraction
    MEMORY_DUMP = "memory_dump"         # Memory analysis
    NETWORK_SNIFF = "network_sniff"     # Network traffic capture
    SEARCHSPLOIT = "searchsploit"       # SearchSploit exploit results


class HashType(Enum):
    """Supported hash types for cracking."""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    NTLM = "ntlm"
    NETNTLMv1 = "netntlmv1"
    NETNTLMv2 = "netntlmv2"
    WPA_PBKDF2 = "wpa_pbkdf2"       # hashcat mode 2500
    WPA_PMKID = "wpa_pmkid"         # hashcat mode 22000
    KERBEROS = "kerberos"
    BCRYPT = "bcrypt"
    SCRYPT = "scrypt"
    ARGON2 = "argon2"


@dataclass
class Credential:
    """Normalized credential entry."""
    id: str = field(default_factory=lambda: str(uuid4()))
    username: Optional[str] = None
    password: Optional[str] = None
    hash: Optional[str] = None
    hash_type: Optional[HashType] = None
    credential_type: CredentialType = CredentialType.PLAINTEXT
    source: CredentialSource = CredentialSource.SERVICE_BRUTE
    target_id: Optional[str] = None  # Reference to target device/service
    target_address: Optional[str] = None
    target_port: Optional[int] = None
    target_service: Optional[str] = None
    captured_at: datetime = field(default_factory=datetime.utcnow)
    validated: bool = False
    validated_at: Optional[datetime] = None
    validity_status: str = "unknown"  # valid, invalid, unknown, revoked
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    
    def to_hashcat_line(self) -> Optional[str]:
        """Convert to hashcat-compatible line."""
        if self.credential_type == CredentialType.WPA_HANDSHAKE and self.hash:
            return self.hash  # Already in hashcat format
        elif self.credential_type == CredentialType.WPA_PMKID and self.hash:
            return self.hash  # Already in hashcat format
        elif self.hash and self.hash_type:
            if self.username:
                return f"{self.username}:{self.hash}"
            return self.hash
        elif self.password:
            if self.username:
                return f"{self.username}:{self.password}"
            return self.password
        return None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "username": self.username,
            "password": self.password,
            "hash": self.hash,
            "hash_type": self.hash_type.value if self.hash_type else None,
            "credential_type": self.credential_type.value,
            "source": self.source.value,
            "target_id": self.target_id,
            "target_address": self.target_address,
            "target_port": self.target_port,
            "target_service": self.target_service,
            "captured_at": self.captured_at.isoformat(),
            "validated": self.validated,
            "validated_at": self.validated_at.isoformat() if self.validated_at else None,
            "validity_status": self.validity_status,
            "metadata": self.metadata,
            "tags": self.tags,
        }
    
    @classmethod
    def from_hashcat_line(cls, line: str, hash_type: HashType, source: CredentialSource = CredentialSource.SERVICE_BRUTE) -> "Credential":
        """Create credential from hashcat output line."""
        parts = line.split(":", 1)
        if len(parts) == 2:
            return cls(
                username=parts[0],
                hash=parts[1],
                hash_type=hash_type,
                credential_type=CredentialType.HASH,
                source=source,
            )
        return cls(
            hash=line,
            hash_type=hash_type,
            credential_type=CredentialType.HASH,
            source=source,
        )


@dataclass
class CredentialSet:
    """Collection of related credentials."""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    credentials: List[Credential] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add(self, cred: Credential):
        self.credentials.append(cred)
    
    def deduplicate(self) -> int:
        """Remove duplicate credentials. Returns count removed."""
        seen: Set[str] = set()
        unique: List[Credential] = []
        removed = 0
        
        for cred in self.credentials:
            # Create unique key based on credential content
            if cred.hash:
                key = f"{cred.hash_type.value if cred.hash_type else 'hash'}:{cred.hash}"
            elif cred.password:
                key = f"plain:{cred.username or ''}:{cred.password}"
            else:
                key = f"unknown:{cred.id}"
            
            if key not in seen:
                seen.add(key)
                unique.append(cred)
            else:
                removed += 1
        
        self.credentials = unique
        return removed


class CredentialManager:
    """
    Central credential management system.
    
    Features:
    - Credential normalization from multiple sources
    - Deduplication with configurable matching
    - Hashcat integration for offline cracking
    - Validation against live targets
    - Export to multiple formats
    - Tagging and categorization
    """
    
    def __init__(
        self,
        storage_path: str = "/var/lib/urban-hs/credentials",
        hashcat_path: str = "hashcat",
        potentiometer_path: str = "/usr/share/wordlists",
        default_rules: str = "/usr/share/hashcat/rules/best64.rule",
    ):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        self.hashcat_path = hashcat_path
        self.wordlists_path = Path(potentiometer_path)
        self.default_rules = default_rules
        
        self._credentials: Dict[str, Credential] = {}  # id -> Credential
        self._cred_sets: Dict[str, CredentialSet] = {}
        self._index_by_target: Dict[str, List[str]] = {}  # target_id -> credential_ids
        self._index_by_hash: Dict[str, str] = {}  # hash -> credential_id
        self._index_by_plain: Dict[str, str] = {}  # username:password -> credential_id
        
        # Hashcat configuration
        self.hashcat_modes = {
            HashType.MD5: 0,
            HashType.SHA1: 100,
            HashType.SHA256: 1400,
            HashType.SHA512: 1700,
            HashType.NTLM: 1000,
            HashType.NETNTLMv1: 9500,
            HashType.NETNTLMv2: 9600,
            HashType.WPA_PBKDF2: 2500,
            HashType.WPA_PMKID: 22000,
            HashType.KERBEROS: 13100,
            HashType.BCRYPT: 3200,
        }
    
    def add(self, credential: Credential) -> bool:
        """Add a credential. Returns True if new, False if duplicate."""
        # Check for duplicate
        if credential.hash:
            key = f"{credential.hash_type.value if credential.hash_type else 'hash'}:{credential.hash}"
            if key in self._index_by_hash:
                existing_id = self._index_by_hash[key]
                # Merge metadata
                existing = self._credentials[existing_id]
                existing.metadata.update(credential.metadata)
                existing.tags = list(set(existing.tags + credential.tags))
                existing.validity_status = "unknown"  # Re-validate
                return False
            self._index_by_hash[key] = credential.id
        elif credential.username and credential.password:
            key = f"{credential.username}:{credential.password}"
            if key in self._index_by_plain:
                existing_id = self._index_by_plain[key]
                existing = self._credentials[existing_id]
                existing.metadata.update(credential.metadata)
                existing.tags = list(set(existing.tags + credential.tags))
                return False
            self._index_by_plain[key] = credential.id
        
        self._credentials[credential.id] = credential
        
        # Index by target
        if credential.target_id:
            self._index_by_target.setdefault(credential.target_id, []).append(credential.id)
        
        return True
    
    def add_from_source(
        self,
        username: Optional[str],
        password: Optional[str],
        hash: Optional[str],
        hash_type: Optional[HashType],
        credential_type: CredentialType,
        source: CredentialSource,
        target_id: Optional[str] = None,
        target_address: Optional[str] = None,
        target_port: Optional[int] = None,
        target_service: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tags: Optional[List[str]] = None,
    ) -> Credential:
        """Create and add credential from raw components."""
        cred = Credential(
            username=username,
            password=password,
            hash=hash,
            hash_type=hash_type,
            credential_type=credential_type,
            source=source,
            target_id=target_id,
            target_address=target_address,
            target_port=target_port,
            target_service=target_service,
            metadata=metadata or {},
            tags=tags or [],
        )
        self.add(cred)
        return cred
    
    def import_from_hashcat_potfile(
        self,
        potfile_path: str,
        hash_type: HashType,
        source: CredentialSource = CredentialSource.WIFI_CRACK,
    ) -> int:
        """Import cracked credentials from hashcat potfile."""
        imported = 0
        try:
            with open(potfile_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or not ':' in line:
                        continue
                    
                    parts = line.split(':', 1)
                    if len(parts) != 2:
                        continue
                    
                    hash_val, password = parts
                    cred = self.add_from_source(
                        username=None,
                        password=password,
                        hash=hash_val,
                        hash_type=hash_type,
                        credential_type=CredentialType.HASH,
                        source=source,
                        tags=["potfile_import"],
                    )
                    # Update with cracked password
                    cred.password = password
                    cred.validated = True
                    cred.validated_at = datetime.utcnow()
                    cred.validity_status = "valid"
                    imported += 1
        except Exception as e:
            logger.error("Failed to import potfile", path=potfile_path, error=str(e))
        
        return imported
    
    def import_from_metasploit_creds(self, creds_data: List[Dict[str, Any]]) -> int:
        """Import credentials from Metasploit db_creds export."""
        imported = 0
        for cred_data in creds_data:
            cred = self.add_from_source(
                username=cred_data.get("user"),
                password=cred_data.get("pass"),
                hash=cred_data.get("hash"),
                hash_type=HashType(cred_data.get("type")) if cred_data.get("type") else None,
                credential_type=CredentialType.PLAINTEXT if cred_data.get("pass") else CredentialType.HASH,
                source=CredentialSource.METASPLOIT,
                target_address=cred_data.get("host"),
                target_port=cred_data.get("port"),
                target_service=cred_data.get("service"),
                metadata={"metasploit_id": cred_data.get("id")},
                tags=["metasploit_import"],
            )
            imported += 1
        return imported
    
    def import_from_searchsploit(self, creds_data: List[Dict[str, Any]]) -> int:
        """Import credentials from SearchSploit results."""
        imported = 0
        for cred_data in creds_data:
            cred = self.add_from_source(
                username=cred_data.get("user"),
                password=cred_data.get("pass"),
                hash=cred_data.get("hash"),
                hash_type=None,
                credential_type=CredentialType.PLAINTEXT,
                source=CredentialSource.SEARCHSPLOIT,  # Best match
                target_address=cred_data.get("host"),
                target_port=cred_data.get("port"),
                target_service=cred_data.get("service"),
                tags=["searchsploit_import"],
            )
            imported += 1
        return imported
    
    def get_for_target(self, target_id: str) -> List[Credential]:
        """Get all credentials for a target."""
        ids = self._index_by_target.get(target_id, [])
        return [self._credentials[id] for id in ids if id in self._credentials]
    
    def get_by_address(self, address: str) -> List[Credential]:
        """Get credentials for a specific IP/hostname."""
        results = []
        for cred in self._credentials.values():
            if cred.target_address == address:
                results.append(cred)
        return results
    
    def get_validated(self) -> List[Credential]:
        """Get all validated credentials."""
        return [c for c in self._credentials.values() if c.validated]
    
    def get_by_type(self, cred_type: CredentialType) -> List[Credential]:
        """Get credentials by type."""
        return [c for c in self._credentials.values() if c.credential_type == cred_type]
    
    def get_by_source(self, source: CredentialSource) -> List[Credential]:
        """Get credentials by source."""
        return [c for c in self._credentials.values() if c.source == source]
    
    def validate_credential(
        self,
        credential: Credential,
        target_address: str,
        target_port: Optional[int] = None,
        service: str = "ssh",
    ) -> bool:
        """Validate a credential against a live target."""
        # This would use hydra, sshpass, or similar tools
        # Implementation depends on service type
        logger.info("Validating credential", target=target_address, service=service)
        
        # Placeholder - actual implementation would use service-specific validation
        credential.validated = True
        credential.validated_at = datetime.utcnow()
        credential.validity_status = "valid"
        return True
    
    async def crack_hashes(
        self,
        hashes_file: str,
        hash_type: HashType,
        wordlist: Optional[str] = None,
        rules_file: Optional[str] = None,
        attack_mode: int = 0,  # 0 = straight, 3 = brute force
        extra_args: List[str] = field(default_factory=list),
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> Dict[str, Any]:
        """
        Run hashcat to crack hashes.
        
        Args:
            hashes_file: Path to file containing hashes (one per line or hashcat format)
            hash_type: Type of hashes
            wordlist: Path to wordlist (default: rockyou.txt)
            rules_file: Path to rules file (default: best64.rule)
            attack_mode: hashcat attack mode (0=straight, 3=brute)
            extra_args: Additional hashcat arguments
            progress_callback: Callback for progress updates
        
        Returns:
            Dict with cracking results
        """
        mode = self.hashcat_modes.get(hash_type)
        if mode is None:
            raise ValueError(f"Unsupported hash type: {hash_type}")
        
        wordlist = wordlist or str(self.wordlists_path / "rockyou.txt")
        rules_file = rules_file or self.default_rules
        extra_args = extra_args or []
        
        if not Path(wordlist).exists():
            logger.warning("Wordlist not found", path=wordlist)
            # Try common locations
            for alt in ["/usr/share/wordlists/rockyou.txt", "/usr/share/dict/rockyou.txt"]:
                if Path(alt).exists():
                    wordlist = alt
                    break
        
        potfile = self.storage_path / "cracked.pot"
        potfile.parent.mkdir(parents=True, exist_ok=True)
        
        cmd = [
            self.hashcat_path,
            "-m", str(mode),
            "-a", str(attack_mode),
            "-w", "3",
            "--potfile-path", str(potfile),
            "--status",
            "--status-timer", "10",
        ]
        
        if attack_mode == 0:
            cmd.extend([hashes_file, wordlist])
            if rules_file and Path(rules_file).exists():
                cmd.extend(["-r", rules_file])
        elif attack_mode == 3:
            cmd.extend([hashes_file])
            # Brute force mask
            extra_args.extend(["?l?l?l?l?l?l?l?l"])
        
        cmd.extend(extra_args)
        
        logger.info("Starting hashcat", cmd=" ".join(cmd), mode=mode)
        
        if progress_callback:
            progress_callback(f"Starting hashcat mode {mode} ({hash_type.value})...")
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,
            )
            
            cracked = []
            if proc.stdout:
                while True:
                    line = await proc.stdout.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").strip()
                    if decoded:
                        if progress_callback:
                            progress_callback(decoded)
                        # Parse hashcat status output for cracked hashes
                        if "Cracked" in decoded or "Status:" in decoded:
                            pass  # Could parse for real-time updates
            
            await proc.wait()
            
            # Import results from potfile
            imported = self.import_from_hashcat_potfile(str(potfile), hash_type)
            
            return {
                "success": proc.returncode == 0,
                "imported": imported,
                "potfile": str(potfile),
                "wordlist": wordlist,
            }
            
        except Exception as e:
            logger.error("Hashcat cracking failed", error=str(e))
            return {"success": False, "error": str(e)}
    
    def create_hash_file(
        self,
        hash_type: HashType,
        credentials: List[Credential],
        output_path: str,
    ) -> int:
        """Create hash file for hashcat from credentials."""
        count = 0
        with open(output_path, 'w') as f:
            for cred in credentials:
                if cred.hash and cred.hash_type == hash_type:
                    line = cred.to_hashcat_line()
                    if line:
                        f.write(line + "\n")
                        count += 1
        return count
    
    def export_to_hashcat(
        self,
        hash_type: Optional[HashType] = None,
        source: Optional[CredentialSource] = None,
    ) -> str:
        """Export credentials to hashcat format file."""
        timestamp = int(time.time())
        filename = f"hashes_{hash_type.value if hash_type else 'all'}_{timestamp}.txt"
        path = self.storage_path / "hashcat_exports" / filename
        path.parent.mkdir(parents=True, exist_ok=True)
        
        count = 0
        with open(path, 'w') as f:
            for cred in self._credentials.values():
                if hash_type and cred.hash_type != hash_type:
                    continue
                if source and cred.source != source:
                    continue
                if cred.hash:
                    line = cred.to_hashcat_line()
                    if line:
                        f.write(line + "\n")
                        count += 1
        
        logger.info("Exported to hashcat format", path=str(path), count=count)
        return str(path)
    
    def export_to_csv(self, path: str) -> int:
        """Export all credentials to CSV."""
        import csv
        count = 0
        with open(path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                "id", "username", "password", "hash", "hash_type",
                "credential_type", "source", "target_address",
                "target_port", "target_service", "captured_at",
                "validated", "validity_status", "tags"
            ])
            for cred in self._credentials.values():
                writer.writerow([
                    cred.id, cred.username or "", cred.password or "",
                    cred.hash or "", cred.hash_type.value if cred.hash_type else "",
                    cred.credential_type.value, cred.source.value,
                    cred.target_address or "", cred.target_port or "",
                    cred.target_service or "", cred.captured_at.isoformat(),
                    cred.validated, cred.validity_status,
                    ",".join(cred.tags),
                ])
                count += 1
        return count
    
    def export_to_json(self, path: str) -> int:
        """Export all credentials to JSON."""
        data = [c.to_dict() for c in self._credentials.values()]
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return len(data)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get credential statistics."""
        stats = {
            "total": len(self._credentials),
            "by_type": {},
            "by_source": {},
            "by_hash_type": {},
            "validated": 0,
            "with_hash": 0,
            "with_password": 0,
        }
        
        for cred in self._credentials.values():
            stats["by_type"][cred.credential_type.value] = stats["by_type"].get(cred.credential_type.value, 0) + 1
            stats["by_source"][cred.source.value] = stats["by_source"].get(cred.source.value, 0) + 1
            
            if cred.validated:
                stats["validated"] += 1
            if cred.hash:
                stats["with_hash"] += 1
                if cred.hash_type:
                    stats["by_hash_type"][cred.hash_type.value] = stats["by_hash_type"].get(cred.hash_type.value, 0) + 1
            if cred.password:
                stats["with_password"] += 1
        
        return stats
    
    def deduplicate_all(self) -> int:
        """Remove all duplicate credentials."""
        # Rebuild indices
        self._index_by_hash.clear()
        self._index_by_plain.clear()
        
        removed = 0
        unique: Dict[str, Credential] = {}
        
        for cred in self._credentials.values():
            if cred.hash:
                key = f"{cred.hash_type.value if cred.hash_type else 'hash'}:{cred.hash}"
                if key in unique:
                    # Merge metadata
                    existing = unique[key]
                    existing.metadata.update(cred.metadata)
                    existing.tags = list(set(existing.tags + cred.tags))
                    removed += 1
                else:
                    unique[key] = cred
                    self._index_by_hash[key] = cred.id
            elif cred.username and cred.password:
                key = f"{cred.username}:{cred.password}"
                if key in unique:
                    existing = unique[key]
                    existing.metadata.update(cred.metadata)
                    existing.tags = list(set(existing.tags + cred.tags))
                    removed += 1
                else:
                    unique[key] = cred
                    self._index_by_plain[key] = cred.id
            else:
                unique[cred.id] = cred
        
        self._credentials = unique
        
        # Rebuild target index
        self._index_by_target.clear()
        for cred in self._credentials.values():
            if cred.target_id:
                self._index_by_target.setdefault(cred.target_id, []).append(cred.id)
        
        return removed
    
    def save_state(self, path: str):
        """Save credential database to file."""
        data = {
            "credentials": [c.to_dict() for c in self._credentials.values()],
            "metadata": {
                "saved_at": datetime.utcnow().isoformat(),
                "version": "1.0",
                "total": len(self._credentials),
            }
        }
        with open(path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
    
    def load_state(self, path: str) -> int:
        """Load credential database from file."""
        with open(path, 'r') as f:
            data = json.load(f)
        
        self._credentials.clear()
        self._index_by_hash.clear()
        self._index_by_plain.clear()
        self._index_by_target.clear()
        
        for cred_data in data.get("credentials", []):
            cred = Credential(
                id=cred_data["id"],
                username=cred_data.get("username"),
                password=cred_data.get("password"),
                hash=cred_data.get("hash"),
                hash_type=HashType(cred_data["hash_type"]) if cred_data.get("hash_type") else None,
                credential_type=CredentialType(cred_data["credential_type"]),
                source=CredentialSource(cred_data["source"]),
                target_id=cred_data.get("target_id"),
                target_address=cred_data.get("target_address"),
                target_port=cred_data.get("target_port"),
                target_service=cred_data.get("target_service"),
                captured_at=datetime.fromisoformat(cred_data["captured_at"]),
                validated=cred_data.get("validated", False),
                validated_at=datetime.fromisoformat(cred_data["validated_at"]) if cred_data.get("validated_at") else None,
                validity_status=cred_data.get("validity_status", "unknown"),
                metadata=cred_data.get("metadata", {}),
                tags=cred_data.get("tags", []),
            )
            self.add(cred)
        
        return len(self._credentials)


# Export all public classes
__all__ = [
    "CredentialType",
    "CredentialSource",
    "HashType",
    "Credential",
    "CredentialSet",
    "CredentialManager",
]