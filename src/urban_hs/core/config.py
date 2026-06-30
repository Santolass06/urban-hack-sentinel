"""
Configuration Management - Pydantic Settings with validation and hot-reload.

Supports YAML/TOML/ENV sources, secrets via keyring, hot-reload via watchfiles.
"""

import asyncio
import os
from pathlib import Path
from typing import Dict, List, Optional, Union

import keyring
import structlog
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from watchfiles import awatch

from urban_hs.core.event_bus import Event, get_event_bus

logger = structlog.get_logger(__name__)


class WiFiConfig(BaseSettings):
    interface: str = "wlan0"
    monitor_interface: Optional[str] = None
    channels_2ghz: List[int] = Field(default_factory=lambda: [1, 6, 11])
    channels_5ghz: List[int] = Field(default_factory=lambda: [36, 40, 44, 48])
    channels_6ghz: List[int] = Field(default_factory=lambda: [])
    scan_interval_sec: int = 5
    passive_scan: bool = True
    tx_power_dbm: Optional[int] = None
    mac_randomize_interval: int = 300  # seconds
    oui_profiles: Dict[str, List[str]] = Field(default_factory=dict)
    enable_active_attacks: bool = False
    legal_warning_shown: bool = False


class BLEConfig(BaseSettings):
    adapter: str = "hci0"
    fast_pair_service_uuid: str = "0000fe2c-0000-1000-8000-00805f9b34fb"
    scan_duration: int = 10
    scan_interval: int = 30
    whisperpair_test_enabled: bool = True
    whisperpair_exploit_enabled: bool = False  # Requires explicit opt-in
    account_key_flood_enabled: bool = False
    hfp_audio_enabled: bool = False
    device_quirks_db: str = "/etc/urban-hs/device_quirks.json"


class NetworkConfig(BaseSettings):
    nmap_timing_template: str = "T3"
    nmap_ports: str = "1-1000"
    nmap_scripts: List[str] = Field(default_factory=lambda: ["vuln", "auth", "default"])
    nuclei_templates: List[str] = Field(default_factory=lambda: ["cves/", "exposures/", "misconfig/"])
    nuclei_severity: List[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    hydra_threads: int = 4
    hydra_timeout: int = 30


class CameraConfig(BaseSettings):
    discovery_protocols: List[str] = Field(default_factory=lambda: ["mdns", "upnp", "onvif", "rtsp"])
    default_creds_file: str = "/etc/urban-hs/camera_default_creds.json"
    onvif_timeout: int = 10
    rtsp_timeout: int = 15
    auth_test_enabled: bool = True
    vuln_check_enabled: bool = True


class MetasploitConfig(BaseSettings):
    rpc_host: str = "127.0.0.1"
    rpc_port: int = 55553
    rpc_user: str = "msf"
    rpc_pass: str = ""
    rpc_ssl: bool = False
    workspace: str = "urban-hs"
    auto_load_modules: bool = True

    @field_validator("rpc_pass", mode="before")
    @classmethod
    def resolve_msf_pass(cls, v: str) -> str:
        if v:
            return v
        # Skip keyring entirely to avoid blocking on headless systems
        return ""


class ChrootConfig(BaseSettings):
    enabled: bool = True
    path: str = "/opt/urban-chroot"
    alpine_version: str = "3.20"
    packages: List[str] = Field(default_factory=lambda: [
        "nmap", "nuclei", "hydra", "metasploit-framework", "hashcat",
        "searchsploit", "bettercap", "routerSploit", "hashcat", "john"
    ])
    bind_mounts: Dict[str, str] = Field(default_factory=lambda: {
        "/data": "/data",
        "/artifacts": "/artifacts",
        "/logs": "/logs",
    })
    resource_limits: Dict[str, Union[int, str]] = Field(default_factory=lambda: {
        "memory": "2G",
        "cpus": "2",
        "pids": "100",
    })


class HIDUSBConfig(BaseSettings):
    hid_enabled: bool = True
    usb_gadget_enabled: bool = True
    keyboard_layouts: List[str] = Field(default_factory=lambda: ["us", "gb", "de", "fr", "es", "it", "ru"])
    default_vid: str = "0x1d6b"
    default_pid: str = "0x0104"
    mass_storage_images_dir: str = ""  # Defaults to {data_root}/mass_storage if empty


class StorageConfig(BaseSettings):
    data_root: str = "/var/lib/urban-hs"
    log_root: str = "/var/log/urban-hs"
    sqlite_path: str = ""  # Defaults to {data_root}/urban.db if empty
    sqlite_wal_mode: bool = True
    sqlite_journal_size: int = 10000
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = 20
    artifact_root: str = ""  # Defaults to {data_root}/artifacts if empty
    wifi_attacks_dir: str = ""  # Defaults to {data_root}/wifi_attacks if empty
    wifi_scans_dir: str = ""  # Defaults to {log_root}/wifi_scans if empty
    evidence_dir: str = ""  # Defaults to {data_root}/evidence if empty
    reports_dir: str = ""  # Defaults to {data_root}/reports if empty
    credentials_dir: str = ""  # Defaults to {data_root}/credentials if empty
    hashes_dir: str = ""  # Defaults to {data_root}/hashes if empty
    pcaps_dir: str = ""  # Defaults to {data_root}/pcaps if empty
    mqtt_attacks_dir: str = ""  # Defaults to {data_root}/mqtt_attacks if empty
    jsonl_dir: str = ""  # Defaults to {log_root}/jsonl if empty
    max_artifact_size_mb: int = 500
    artifact_retention_days: int = 90
    log_retention_days: int = 30

    def resolve_sqlite_path(self) -> str:
        return self.sqlite_path or f"{self.data_root}/urban.db"

    def resolve_artifact_root(self) -> str:
        return self.artifact_root or f"{self.data_root}/artifacts"

    def resolve_wifi_attacks_dir(self) -> str:
        return self.wifi_attacks_dir or f"{self.data_root}/wifi_attacks"

    def resolve_wifi_scans_dir(self) -> str:
        return self.wifi_scans_dir or f"{self.log_root}/wifi_scans"

    def resolve_evidence_dir(self) -> str:
        return self.evidence_dir or f"{self.data_root}/evidence"

    def resolve_reports_dir(self) -> str:
        return self.reports_dir or f"{self.data_root}/reports"

    def resolve_credentials_dir(self) -> str:
        return self.credentials_dir or f"{self.data_root}/credentials"

    def resolve_hashes_dir(self) -> str:
        return self.hashes_dir or f"{self.data_root}/hashes"

    def resolve_pcaps_dir(self) -> str:
        return self.pcaps_dir or f"{self.data_root}/pcaps"

    def resolve_mqtt_attacks_dir(self) -> str:
        return self.mqtt_attacks_dir or f"{self.data_root}/mqtt_attacks"

    def resolve_jsonl_dir(self) -> str:
        return self.jsonl_dir or f"{self.log_root}/jsonl"

    def resolve_mass_storage_dir(self) -> str:
        from urban_hs.core.config import get_config
        cfg = get_config()
        return cfg.hid_usb.mass_storage_images_dir or f"{self.data_root}/mass_storage"


class LoggingConfig(BaseSettings):
    level: str = "INFO"
    json_logs: bool = True
    console_colors: bool = True
    file_rotation: str = "1 day"
    file_retention: str = "30 days"
    correlation_id_header: str = "X-Correlation-ID"


class APIConfig(BaseSettings):
    host: str = "0.0.0.0"
    port: int = 8080
    workers: int = 2
    jwt_secret: str = ""  # Must be set via env/keyring
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60
    cors_origins: List[str] = Field(default_factory=lambda: ["http://localhost:3000"])
    tls_enabled: bool = False
    tls_cert_path: str = ""
    tls_key_path: str = ""

    @field_validator("jwt_secret", mode="before")
    @classmethod
    def resolve_jwt_secret(cls, v: str) -> str:
        if v:
            return v
        # Skip keyring entirely to avoid blocking on headless systems
        import secrets
        return secrets.token_urlsafe(32)


class Config(BaseSettings):
    """Master configuration with all sub-configs."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    wifi: WiFiConfig = Field(default_factory=WiFiConfig)
    ble: BLEConfig = Field(default_factory=BLEConfig)
    network: NetworkConfig = Field(default_factory=NetworkConfig)
    camera: CameraConfig = Field(default_factory=CameraConfig)
    metasploit: MetasploitConfig = Field(default_factory=MetasploitConfig)
    chroot: ChrootConfig = Field(default_factory=ChrootConfig)
    hid_usb: HIDUSBConfig = Field(default_factory=HIDUSBConfig)
    storage: StorageConfig = Field(default_factory=StorageConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    api: APIConfig = Field(default_factory=APIConfig)

    # Global settings
    debug: bool = False
    dry_run: bool = False
    config_file: Optional[str] = None

    def get_secret(self, service: str, username: str) -> str:
        """Retrieve secret from keyring."""
        return keyring.get_password(service, username) or ""

    def set_secret(self, service: str, username: str, password: str) -> None:
        """Store secret in keyring."""
        keyring.set_password(service, username, password)


def resolve_data_path(subpath: str) -> Path:
    """Resolve a path under the data root from Config."""
    cfg = get_config()
    return Path(cfg.storage.data_root) / subpath


def resolve_log_path(subpath: str) -> Path:
    """Resolve a path under the log root from Config."""
    cfg = get_config()
    return Path(cfg.storage.log_root) / subpath


# Global config instance
_config: Optional[Config] = None
_config_watch_task: Optional[asyncio.Task] = None


def get_config() -> Config:
    global _config
    if _config is None:
        _config = Config()
    return _config


async def init_config(config_file: Optional[str] = None, watch: bool = True) -> Config:
    """Initialize configuration with optional hot-reload."""
    global _config, _config_watch_task
    
    if config_file:
        os.environ["URBAN_HS_CONFIG_FILE"] = config_file
    
    _config = Config(config_file=config_file)
    
    if watch:
        _config_watch_task = asyncio.create_task(_watch_config())
    
    # Publish config loaded event
    bus = get_event_bus()
    await bus.publish(Event(
        type="config.loaded",
        payload=_config.model_dump(mode="json"),
        source="config",
    ))
    
    return _config


async def _watch_config() -> None:
    """Watch config file for changes and hot-reload."""
    config_file = os.environ.get("URBAN_HS_CONFIG_FILE")
    if not config_file or not os.path.exists(config_file):
        return
    
    config = get_config()
    bus = get_event_bus()
    
    async for changes in awatch(config_file):
        if not changes:
            continue
        try:
            # Reload config
            old_config = config.model_dump()
            config = Config(config_file=config_file)
            globals()["_config"] = config
            
            # Publish reload event
            await bus.publish(Event(
                type="config.reloaded",
                payload=config.model_dump(mode="json"),
                metadata={"changes": [str(c) for c in changes]},
                source="config",
            ))
        except Exception as e:
            logger.error("Config reload failed", error=str(e))


async def shutdown_config() -> None:
    global _config_watch_task
    if _config_watch_task:
        _config_watch_task.cancel()
        try:
            await _config_watch_task
        except asyncio.CancelledError:
            pass