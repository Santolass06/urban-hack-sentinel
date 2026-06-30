"""
Storage Layer - SQLite (aiosqlite) with WAL mode, migrations, and Redis cache.

Provides:
- Async SQLite with connection pooling
- Automatic schema migrations
- Redis cache with pub/sub for cross-process events
- Structured logging to JSONL
"""

import asyncio
import json
import os
import structlog
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple, Union

import aiosqlite

try:
    import redis.asyncio as redis
except ImportError:
    redis = None  # type: ignore[assignment]

logger = structlog.get_logger(__name__)

SCHEMA_VERSION = 1

SCHEMA = """
-- Core tables
CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    first_seen INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    type TEXT NOT NULL,
    mac TEXT,
    ip TEXT,
    vendor TEXT,
    labels TEXT,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_devices_type ON devices(type);
CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen);
CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);

CREATE TABLE IF NOT EXISTS wifi_networks (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    ssid TEXT,
    bssid TEXT NOT NULL UNIQUE,
    encryption TEXT,
    channel INTEGER,
    frequency INTEGER,
    signal_dbm INTEGER,
    bandwidth TEXT,
    wps_enabled INTEGER DEFAULT 0,
    wps_locked INTEGER DEFAULT 0,
    pmf TEXT,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_wifi_bssid ON wifi_networks(bssid);

CREATE TABLE IF NOT EXISTS wifi_handshakes (
    id TEXT PRIMARY KEY,
    network_id TEXT REFERENCES wifi_networks(device_id) ON DELETE SET NULL,
    bssid TEXT NOT NULL,
    essid TEXT,
    capture_path TEXT NOT NULL,
    hash_path TEXT,
    hashcat_mode INTEGER,
    crack_status TEXT DEFAULT 'uncracked',
    password TEXT,
    cracked_at INTEGER,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_handshakes_bssid ON wifi_handshakes(bssid);
CREATE INDEX IF NOT EXISTS idx_handshakes_status ON wifi_handshakes(crack_status);

CREATE TABLE IF NOT EXISTS ble_devices (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    address_type TEXT,
    name TEXT,
    rssi INTEGER,
    tx_power INTEGER,
    services TEXT,
    manufacturer_data TEXT,
    is_fast_pair INTEGER DEFAULT 0,
    fast_pair_model_id TEXT,
    fast_pair_mode TEXT,
    whisperpair_vuln TEXT,
    whisperpair_exploited INTEGER DEFAULT 0,
    account_key_written INTEGER DEFAULT 0,
    hfp_connected INTEGER DEFAULT 0,
    audio_recordings INTEGER DEFAULT 0,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS bt_classic_devices (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    name TEXT,
    class_of_device INTEGER,
    services TEXT,
    paired INTEGER DEFAULT 0,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS cameras (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    port INTEGER,
    protocol TEXT,
    manufacturer TEXT,
    model TEXT,
    firmware TEXT,
    auth_required INTEGER,
    default_creds TEXT,
    rtsp_url TEXT,
    snapshot_url TEXT,
    vulnerable INTEGER DEFAULT 0,
    cves TEXT,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_cameras_ip ON cameras(ip);

CREATE TABLE IF NOT EXISTS network_hosts (
    device_id TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    os_guess TEXT,
    ports_open TEXT,
    vulns TEXT,
    meta TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
    id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
    target_type TEXT,
    cve_id TEXT,
    name TEXT,
    severity TEXT,
    exploit_available INTEGER DEFAULT 0,
    exploit_path TEXT,
    metasploit_module TEXT,
    nuclei_template TEXT,
    status TEXT DEFAULT 'identified',
    exploited_at INTEGER,
    proof TEXT,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_vulns_target ON vulnerabilities(target_id);
CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);

CREATE TABLE IF NOT EXISTS credentials (
    id TEXT PRIMARY KEY,
    target_id TEXT REFERENCES devices(id) ON DELETE CASCADE,
    target_type TEXT,
    username TEXT,
    password TEXT,
    hash TEXT,
    hash_type TEXT,
    source TEXT,
    captured_at INTEGER NOT NULL,
    meta TEXT
);

CREATE INDEX IF NOT EXISTS idx_creds_target ON credentials(target_id);
CREATE INDEX IF NOT EXISTS idx_creds_source ON credentials(source);

CREATE TABLE IF NOT EXISTS audit_sessions (
    id TEXT PRIMARY KEY,
    started_at INTEGER NOT NULL,
    ended_at INTEGER,
    config_snapshot TEXT,
    stats TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    session_id TEXT REFERENCES audit_sessions(id) ON DELETE CASCADE,
    type TEXT,
    path TEXT NOT NULL,
    mime_type TEXT,
    size_bytes INTEGER,
    meta TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_type ON artifacts(type);
"""

class Storage:
    """
    Async SQLite storage with Redis cache.
    
    Features:
    - WAL mode for concurrent reads
    - Connection pooling
    - Automatic migrations
    - Redis cache with pub/sub
    - JSONL logging
    """

    def __init__(
        self,
        sqlite_path: Optional[str] = None,
        redis_url: Optional[str] = None,
        wal_mode: bool = True,
        journal_size: int = 10000,
        pool_size: int = 5,
    ):
        if sqlite_path is None or redis_url is None:
            from urban_hs.core.config import get_config
            cfg = get_config()
            if sqlite_path is None:
                sqlite_path = cfg.storage.resolve_sqlite_path()
            if redis_url is None:
                redis_url = cfg.storage.redis_url
        self.sqlite_path = Path(sqlite_path)
        self.redis_url = redis_url
        self.wal_mode = wal_mode
        self.journal_size = journal_size
        self.pool_size = pool_size
        
        self._pool: asyncio.Queue[aiosqlite.Connection] = asyncio.Queue(maxsize=pool_size)
        self._redis: Optional[redis.Redis] = None
        self._initialized = False
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Initialize database and connection pool."""
        if self._initialized:
            return

        # Ensure directory exists
        self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize pool
        for _ in range(self.pool_size):
            conn = await aiosqlite.connect(self.sqlite_path)
            conn.row_factory = aiosqlite.Row
            if self.wal_mode:
                await conn.execute("PRAGMA journal_mode=WAL")
            await conn.execute("PRAGMA busy_timeout=30000")
            await conn.execute(f"PRAGMA journal_size_limit={self.journal_size}")
            await self._pool.put(conn)

        # Run migrations
        await self._migrate()

        # Initialize Redis
        try:
            if redis is not None and self.redis_url:
                self._redis = redis.from_url(self.redis_url, decode_responses=True)
            else:
                self._redis = None
        except Exception as e:
            logger.warning("Failed to connect to Redis, continuing without cache", error=str(e))
            self._redis = None

        self._initialized = True
        logger.info("Storage initialized", path=str(self.sqlite_path), pool_size=self.pool_size)

    async def _migrate(self) -> None:
        """Run schema migrations."""
        async with self._get_conn() as conn:
            # Check current version - handle case where table doesn't exist yet
            try:
                cursor = await conn.execute(
                    "SELECT version FROM schema_version ORDER BY version DESC LIMIT 1"
                )
                row = await cursor.fetchone()
                current_version = row[0] if row else 0
            except aiosqlite.OperationalError:
                # Table doesn't exist yet, will be created by SCHEMA
                current_version = 0

            if current_version < SCHEMA_VERSION:
                logger.info("Running migration", from_version=current_version, to_version=SCHEMA_VERSION)
                await conn.executescript(SCHEMA)
                await conn.execute(
                    "INSERT OR REPLACE INTO schema_version (version, applied_at) VALUES (?, ?)",
                    (SCHEMA_VERSION, int(datetime.utcnow().timestamp())),
                )
                await conn.commit()
                logger.info("Migration completed", version=SCHEMA_VERSION)

    @asynccontextmanager
    async def _get_conn(self) -> AsyncIterator[aiosqlite.Connection]:
        """Get connection from pool."""
        conn = await self._pool.get()
        try:
            yield conn
        finally:
            await self._pool.put(conn)

    async def execute(self, query: str, params: tuple = ()) -> None:
        """Execute a write query."""
        async with self._get_conn() as conn:
            await conn.execute(query, params)
            await conn.commit()

    async def executemany(self, query: str, params_list: List[tuple]) -> None:
        """Execute multiple write queries."""
        async with self._get_conn() as conn:
            await conn.executemany(query, params_list)
            await conn.commit()

    async def fetchone(self, query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetch single row as dict."""
        async with self._get_conn() as conn:
            cursor = await conn.execute(query, params)
            row = await cursor.fetchone()
            return dict(row) if row else None

    async def fetchall(self, query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetch all rows as list of dicts."""
        async with self._get_conn() as conn:
            cursor = await conn.execute(query, params)
            rows = await cursor.fetchall()
            return [dict(row) for row in rows]

    async def fetch_iter(self, query: str, params: tuple = ()) -> AsyncIterator[Dict[str, Any]]:
        """Iterate over rows without loading all into memory."""
        async with self._get_conn() as conn:
            cursor = await conn.execute(query, params)
            async for row in cursor:
                yield dict(row)

    # Redis cache methods
    async def cache_set(self, key: str, value: Any, ttl: int = 3600) -> bool:
        """Set cache value with TTL."""
        if not self._redis:
            return False
        try:
            serialized = json.dumps(value, default=str) if not isinstance(value, str) else value
            return await self._redis.setex(key, ttl, serialized)
        except Exception as e:
            logger.warning("Cache set failed", key=key, error=str(e))
            return False

    async def cache_get(self, key: str, default: Any = None) -> Any:
        """Get cache value."""
        if not self._redis:
            return default
        try:
            value = await self._redis.get(key)
            if value is None:
                return default
            try:
                return json.loads(value)
            except json.JSONDecodeError:
                return value
        except Exception as e:
            logger.warning("Cache get failed", key=key, error=str(e))
            return default

    async def cache_delete(self, key: str) -> bool:
        """Delete cache key."""
        if not self._redis:
            return False
        try:
            return await self._redis.delete(key) > 0
        except Exception as e:
            logger.warning("Cache delete failed", key=key, error=str(e))
            return False

    async def cache_exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        if not self._redis:
            return False
        try:
            return await self._redis.exists(key) > 0
        except Exception:
            return False

    # Pub/Sub
    async def publish(self, channel: str, message: Any) -> int:
        """Publish message to Redis channel."""
        if not self._redis:
            return 0
        try:
            serialized = json.dumps(message, default=str) if not isinstance(message, str) else message
            return await self._redis.publish(channel, serialized)
        except Exception as e:
            logger.warning("Publish failed", channel=channel, error=str(e))
            return 0

    async def subscribe(self, channel: str) -> AsyncIterator[Any]:
        """Subscribe to Redis channel."""
        if not self._redis:
            return
        pubsub = self._redis.pubsub()
        await pubsub.subscribe(channel)
        try:
            async for message in pubsub.listen():
                if message["type"] == "message":
                    try:
                        yield json.loads(message["data"])
                    except json.JSONDecodeError:
                        yield message["data"]
        finally:
            await pubsub.unsubscribe(channel)
            await pubsub.close()

    # Device CRUD
    async def upsert_device(self, device: Dict[str, Any]) -> None:
        """Insert or update device."""
        await self.execute("""
            INSERT INTO devices (id, first_seen, last_seen, type, mac, ip, vendor, labels, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                last_seen=excluded.last_seen,
                ip=excluded.ip,
                vendor=excluded.vendor,
                labels=excluded.labels,
                meta=excluded.meta
        """, (
            device["id"],
            device["first_seen"],
            device["last_seen"],
            device["type"],
            device.get("mac"),
            device.get("ip"),
            device.get("vendor"),
            json.dumps(device.get("labels", [])),
            json.dumps(device.get("meta", {})),
        ))

    async def get_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        return await self.fetchone("SELECT * FROM devices WHERE id=?", (device_id,))

    async def list_devices(
        self,
        device_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if device_type:
            return await self.fetchall(
                "SELECT * FROM devices WHERE type=? ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (device_type, limit, offset),
            )
        return await self.fetchall(
            "SELECT * FROM devices ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    # WiFi Network CRUD
    async def upsert_wifi_network(self, network: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO wifi_networks (device_id, ssid, bssid, encryption, channel, frequency, signal_dbm, bandwidth, wps_enabled, wps_locked, pmf, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(bssid) DO UPDATE SET
                ssid=excluded.ssid,
                encryption=excluded.encryption,
                channel=excluded.channel,
                frequency=excluded.frequency,
                signal_dbm=excluded.signal_dbm,
                bandwidth=excluded.bandwidth,
                wps_enabled=excluded.wps_enabled,
                wps_locked=excluded.wps_locked,
                pmf=excluded.pmf,
                meta=excluded.meta
        """, (
            network["device_id"],
            network.get("ssid"),
            network["bssid"],
            network.get("encryption"),
            network.get("channel"),
            network.get("frequency"),
            network.get("signal_dbm"),
            network.get("bandwidth"),
            int(network.get("wps_enabled", False)),
            int(network.get("wps_locked", False)),
            network.get("pmf"),
            json.dumps(network.get("meta", {})),
        ))

    async def get_wifi_network(self, bssid: str) -> Optional[Dict[str, Any]]:
        return await self.fetchone("SELECT * FROM wifi_networks WHERE bssid=?", (bssid,))

    async def list_wifi_networks(
        self,
        encryption: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        if encryption:
            return await self.fetchall(
                "SELECT * FROM wifi_networks WHERE encryption=? ORDER BY signal_dbm DESC LIMIT ? OFFSET ?",
                (encryption, limit, offset),
            )
        return await self.fetchall(
            "SELECT * FROM wifi_networks ORDER BY signal_dbm DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    # Handshake CRUD
    async def upsert_handshake(self, handshake: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO wifi_handshakes (id, network_id, bssid, essid, capture_path, hash_path, hashcat_mode, crack_status, password, cracked_at, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                network_id=excluded.network_id,
                hash_path=excluded.hash_path,
                hashcat_mode=excluded.hashcat_mode,
                crack_status=excluded.crack_status,
                password=excluded.password,
                cracked_at=excluded.cracked_at,
                meta=excluded.meta
        """, (
            handshake["id"],
            handshake.get("network_id"),
            handshake["bssid"],
            handshake.get("essid"),
            handshake["capture_path"],
            handshake.get("hash_path"),
            handshake.get("hashcat_mode"),
            handshake.get("crack_status", "uncracked"),
            handshake.get("password"),
            handshake.get("cracked_at"),
            json.dumps(handshake.get("meta", {})),
        ))

    async def list_handshakes(self, status: Optional[str] = None, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        if status:
            return await self.fetchall(
                "SELECT * FROM wifi_handshakes WHERE crack_status=? ORDER BY cracked_at DESC LIMIT ? OFFSET ?",
                (status, limit, offset),
            )
        return await self.fetchall(
            "SELECT * FROM wifi_handshakes ORDER BY cracked_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        )

    # BLE Device CRUD
    async def upsert_ble_device(self, device: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO ble_devices (device_id, address_type, name, rssi, tx_power, services, manufacturer_data,
                is_fast_pair, fast_pair_model_id, fast_pair_mode, whisperpair_vuln, whisperpair_exploited,
                account_key_written, hfp_connected, audio_recordings, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_id) DO UPDATE SET
                name=excluded.name,
                rssi=excluded.rssi,
                tx_power=excluded.tx_power,
                services=excluded.services,
                manufacturer_data=excluded.manufacturer_data,
                is_fast_pair=excluded.is_fast_pair,
                fast_pair_model_id=excluded.fast_pair_model_id,
                fast_pair_mode=excluded.fast_pair_mode,
                whisperpair_vuln=excluded.whisperpair_vuln,
                whisperpair_exploited=excluded.whisperpair_exploited,
                account_key_written=excluded.account_key_written,
                hfp_connected=excluded.hfp_connected,
                audio_recordings=excluded.audio_recordings,
                meta=excluded.meta
        """, (
            device["device_id"],
            device.get("address_type"),
            device.get("name"),
            device.get("rssi"),
            device.get("tx_power"),
            json.dumps(device.get("services", [])),
            json.dumps(device.get("manufacturer_data", {})),
            int(device.get("is_fast_pair", False)),
            device.get("fast_pair_model_id"),
            device.get("fast_pair_mode"),
            device.get("whisperpair_vuln"),
            int(device.get("whisperpair_exploited", False)),
            int(device.get("account_key_written", False)),
            int(device.get("hfp_connected", False)),
            device.get("audio_recordings", 0),
            json.dumps(device.get("meta", {})),
        ))

    async def get_ble_device(self, device_id: str) -> Optional[Dict[str, Any]]:
        return await self.fetchone("SELECT * FROM ble_devices WHERE device_id=?", (device_id,))

    # Vulnerability CRUD
    async def upsert_vulnerability(self, vuln: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO vulnerabilities (id, target_id, target_type, cve_id, name, severity, exploit_available,
                exploit_path, metasploit_module, nuclei_template, status, exploited_at, proof, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                status=excluded.status,
                exploited_at=excluded.exploited_at,
                proof=excluded.proof,
                meta=excluded.meta
        """, (
            vuln["id"],
            vuln["target_id"],
            vuln["target_type"],
            vuln.get("cve_id"),
            vuln["name"],
            vuln["severity"],
            int(vuln.get("exploit_available", False)),
            vuln.get("exploit_path"),
            vuln.get("metasploit_module"),
            vuln.get("nuclei_template"),
            vuln.get("status", "identified"),
            vuln.get("exploited_at"),
            json.dumps(vuln.get("proof", {})),
            json.dumps(vuln.get("meta", {})),
        ))

    async def list_vulnerabilities(
        self,
        target_id: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if target_id:
            conditions.append("target_id=?")
            params.append(target_id)
        if status:
            conditions.append("status=?")
            params.append(status)
        if severity:
            conditions.append("severity=?")
            params.append(severity)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        return await self.fetchall(
            f"SELECT * FROM vulnerabilities{where} ORDER BY exploited_at DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    # Credentials CRUD
    async def upsert_credential(self, cred: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO credentials (id, target_id, target_type, username, password, hash, hash_type, source, captured_at, meta)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                password=excluded.password,
                hash=excluded.hash,
                meta=excluded.meta
        """, (
            cred["id"],
            cred["target_id"],
            cred["target_type"],
            cred.get("username"),
            cred.get("password"),
            cred.get("hash"),
            cred.get("hash_type"),
            cred["source"],
            cred["captured_at"],
            json.dumps(cred.get("meta", {})),
        ))

    # Artifact CRUD
    async def upsert_artifact(self, artifact: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO artifacts (id, session_id, type, path, mime_type, size_bytes, meta, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                path=excluded.path,
                meta=excluded.meta
        """, (
            artifact["id"],
            artifact.get("session_id"),
            artifact["type"],
            artifact["path"],
            artifact.get("mime_type"),
            artifact.get("size_bytes"),
            json.dumps(artifact.get("meta", {})),
            artifact["created_at"],
        ))

    async def list_artifacts(
        self,
        session_id: Optional[str] = None,
        artifact_type: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        conditions = []
        params = []

        if session_id:
            conditions.append("session_id=?")
            params.append(session_id)
        if artifact_type:
            conditions.append("type=?")
            params.append(artifact_type)

        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        params.extend([limit, offset])

        return await self.fetchall(
            f"SELECT * FROM artifacts{where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    # Audit Session CRUD
    async def create_session(self, session: Dict[str, Any]) -> None:
        await self.execute("""
            INSERT INTO audit_sessions (id, started_at, config_snapshot, stats, notes)
            VALUES (?, ?, ?, ?, ?)
        """, (
            session["id"],
            session["started_at"],
            json.dumps(session.get("config_snapshot", {})),
            json.dumps(session.get("stats", {})),
            session.get("notes", ""),
        ))

    async def end_session(self, session_id: str, stats: Dict[str, Any]) -> None:
        await self.execute("""
            UPDATE audit_sessions SET ended_at=?, stats=? WHERE id=?
        """, (int(datetime.utcnow().timestamp()), json.dumps(stats), session_id))

    # JSONL Logging
    async def log_jsonl(self, table: str, record: Dict[str, Any]) -> None:
        """Append record to JSONL log file for table."""
        import aiofiles
        from urban_hs.core.config import get_config
        log_dir = Path(get_config().storage.resolve_jsonl_dir())
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / f"{table}.jsonl"
        
        record["_logged_at"] = int(datetime.utcnow().timestamp() * 1000)
        line = json.dumps(record, default=str) + "\n"
        
        async with aiofiles.open(log_file, "a") as f:
            await f.write(line)

    async def shutdown(self) -> None:
        """Close all connections."""
        # Close SQLite connections
        while not self._pool.empty():
            conn = await self._pool.get()
            await conn.close()
        
        # Close Redis
        if self._redis:
            await self._redis.aclose()
        
        logger.info("Storage shutdown complete")

    # ============================================================
    # SQLite Optimization (S6.3)
    # ============================================================
    
    async def create_composite_indices(self) -> None:
        """Create composite indices for common query patterns."""
        indices = [
            # Device queries
            "CREATE INDEX IF NOT EXISTS idx_devices_type_last_seen ON devices(type, last_seen DESC);",
            "CREATE INDEX IF NOT EXISTS idx_devices_mac_type ON devices(mac, type);",
            
            # WiFi network queries
            "CREATE INDEX IF NOT EXISTS idx_wifi_encryption_channel ON wifi_networks(encryption, channel);",
            "CREATE INDEX IF NOT EXISTS idx_wifi_signal_encryption ON wifi_networks(signal_dbm DESC, encryption);",
            "CREATE INDEX IF NOT EXISTS idx_wifi_vendor_encryption ON wifi_networks(vendor, encryption);",
            
            # Handshake queries
            "CREATE INDEX IF NOT EXISTS idx_handshakes_network_status ON wifi_handshakes(network_id, crack_status);",
            "CREATE INDEX IF NOT EXISTS idx_handshakes_bssid_status ON wifi_handshakes(bssid, crack_status);",
            
            # BLE device queries
            "CREATE INDEX IF NOT EXISTS idx_ble_name_rssi ON ble_devices(name, rssi DESC);",
            "CREATE INDEX IF NOT EXISTS idx_ble_fastpair_vuln ON ble_devices(is_fast_pair, whisperpair_vuln);",
            "CREATE INDEX IF NOT EXISTS idx_ble_hfp_audio ON ble_devices(hfp_connected, audio_recordings);",
            
            # Camera queries
            "CREATE INDEX IF NOT EXISTS idx_cameras_vuln_manufacturer ON cameras(vulnerable, manufacturer);",
            "CREATE INDEX IF NOT EXISTS idx_cameras_vuln_cves ON cameras(vulnerable, cves);",
            
            # Network host queries
            "CREATE INDEX IF NOT EXISTS idx_hosts_os_vulns ON network_hosts(os_guess, vulns);",
            "CREATE INDEX IF NOT EXISTS idx_hosts_ports_services ON network_hosts(ports_open);",
            
            # Vulnerability queries
            "CREATE INDEX IF NOT EXISTS idx_vulns_type_severity ON vulnerabilities(target_type, severity);",
            "CREATE INDEX IF NOT EXISTS idx_vulns_exploit_available ON vulnerabilities(exploit_available, severity);",
            "CREATE INDEX IF NOT EXISTS idx_vulns_cve_status ON vulnerabilities(cve_id, status);",
            
            # Credential queries
            "CREATE INDEX IF NOT EXISTS idx_creds_type_source ON credentials(target_type, source);",
            "CREATE INDEX IF NOT EXISTS idx_creds_hash_type ON credentials(hash_type, hash);",
            
            # Audit session queries
            "CREATE INDEX IF NOT EXISTS idx_sessions_time_range ON audit_sessions(started_at, ended_at);",
            
            # Artifact queries
            "CREATE INDEX IF NOT EXISTS idx_artifacts_type_time ON artifacts(type, created_at DESC);",
            "CREATE INDEX IF NOT EXISTS idx_artifacts_session_type ON artifacts(session_id, type);",
        ]
        
        for idx in indices:
            try:
                await self.execute(idx)
            except Exception as e:
                logger.warning("Failed to create index", index=idx, error=str(e))
        
        logger.info("Composite indices created", count=len(indices))

    async def optimize_database(self) -> Dict[str, Any]:
        """Run SQLite optimization: ANALYZE, PRAGMA optimize, WAL checkpoint."""
        results = {}
        
        # Get a connection
        async with self._get_conn() as conn:
            # Enable WAL mode if not already enabled
            await conn.execute("PRAGMA journal_mode=WAL;")
            
            # Set busy timeout
            await conn.execute("PRAGMA busy_timeout=5000;")
            
            # Set page size (if not set)
            await conn.execute("PRAGMA page_size=4096;")
            
            # Set cache size (negative = KB, positive = pages)
            await conn.execute("PRAGMA cache_size=-32768;")  # 32MB cache
            
            # Set mmap size
            await conn.execute("PRAGMA mmap_size=268435456;")  # 256MB
            
            # Set synchronous mode
            await conn.execute("PRAGMA synchronous=NORMAL;")
            
            # Set temp store to memory
            await conn.execute("PRAGMA temp_store=MEMORY;")
            
            # Run ANALYZE to update query planner statistics
            await conn.execute("ANALYZE;")
            results["analyze"] = "completed"
            
            # Run PRAGMA optimize (automatically runs ANALYZE on tables that need it)
            await conn.execute("PRAGMA optimize;")
            results["pragma_optimize"] = "completed"
            
            # WAL checkpoint (truncate WAL file)
            checkpoint_result = await conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            results["wal_checkpoint"] = "completed"
            
            # Get database stats
            cursor = await conn.execute("PRAGMA page_count;")
            page_count = await cursor.fetchone()
            cursor = await conn.execute("PRAGMA page_size;")
            page_size = await cursor.fetchone()
            cursor = await conn.execute("PRAGMA freelist_count;")
            freelist = await cursor.fetchone()
            
            results["stats"] = {
                "page_count": page_count[0] if page_count else 0,
                "page_size": page_size[0] if page_size else 0,
                "freelist_count": freelist[0] if freelist else 0,
                "db_size_mb": (page_count[0] * page_size[0]) / (1024 * 1024) if page_count and page_size else 0,
            }
            
            await conn.commit()
        
        logger.info("Database optimization completed", results=results)
        return results
    
    async def vacuum_database(self, full: bool = False) -> Dict[str, Any]:
        """Run VACUUM to reclaim space and defragment database."""
        results: Dict[str, Any] = {"vacuum_type": "FULL" if full else "INCREMENTAL"}
        
        async with self._get_conn() as conn:
            # Get size before
            cursor = await conn.execute("PRAGMA page_count;")
            page_count_before = await cursor.fetchone()
            cursor = await conn.execute("PRAGMA page_size;")
            page_size = await cursor.fetchone()
            size_before = (page_count_before[0] * page_size[0]) / (1024 * 1024) if page_count_before and page_size else 0
            
            if full:
                await conn.execute("VACUUM;")
            else:
                # Incremental vacuum - reclaim up to 100 pages
                await conn.execute("PRAGMA incremental_vacuum(100);")
            
            # Get size after
            cursor = await conn.execute("PRAGMA page_count;")
            page_count_after = await cursor.fetchone()
            cursor = await conn.execute("PRAGMA page_size;")
            page_size = await cursor.fetchone() if page_size is None else page_size
            size_after = (page_count_after[0] * page_size[0]) / (1024 * 1024) if page_count_after and page_size else 0
            
            results["size_before_mb"] = round(size_before, 2)
            results["size_after_mb"] = round(size_after, 2)
            results["space_reclaimed_mb"] = round(size_before - size_after, 2)
            
            await conn.commit()
        
        logger.info("Database vacuum completed", results=results)
        return results

    async def schedule_optimization(self, interval_hours: int = 24) -> None:
        """Schedule periodic database optimization."""
        # This would be called by the scheduler
        # Run optimization
        await self.optimize_database()
        
        # Run incremental vacuum weekly
        await self.vacuum_database(full=False)
        
        # Full vacuum monthly
        # (Would track last full vacuum time)
        
        logger.info("Scheduled optimization completed")
        """Close all connections."""
        # Close SQLite connections
        while not self._pool.empty():
            conn = await self._pool.get()
            await conn.close()
        
        # Close Redis
        if self._redis:
            await self._redis.close()
        
        logger.info("Storage shutdown complete")


# Global instance
_storage: Optional[Storage] = None


def get_storage() -> Storage:
    global _storage
    if _storage is None:
        _storage = Storage()
    return _storage


async def init_storage(**kwargs) -> Storage:
    global _storage
    _storage = Storage(**kwargs)
    await _storage.initialize()
    return _storage


async def shutdown_storage() -> None:
    global _storage
    if _storage:
        await _storage.shutdown()
        _storage = None