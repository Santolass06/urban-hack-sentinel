"""
Metasploit RPC Client

Provides async interface to Metasploit's msgrpc (MessagePack RPC) service.
Supports module search/execution, session management, and meterpreter interaction.
"""

import asyncio
import msgpack
import structlog
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from urllib.parse import urlparse

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

logger = structlog.get_logger(__name__)


class MsfModuleType(Enum):
    """Metasploit module types."""
    EXPLOIT = "exploit"
    AUXILIARY = "auxiliary"
    POST = "post"
    PAYLOAD = "payload"
    ENCODER = "encoder"
    NOP = "nop"
    EVASION = "evasion"


class MsfSessionType(Enum):
    """Metasploit session types."""
    METERPRETER = "meterpreter"
    SHELL = "shell"
    VNC = "vnc"
    UNKNOWN = "unknown"


@dataclass
class MsfModule:
    """Metasploit module information."""
    fullname: str
    name: str
    type: MsfModuleType
    description: str
    references: List[str] = field(default_factory=list)
    authors: List[str] = field(default_factory=list)
    platform: List[str] = field(default_factory=list)
    arch: List[str] = field(default_factory=list)
    targets: List[Dict[str, Any]] = field(default_factory=list)
    options: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    required_options: List[str] = field(default_factory=list)
    advanced_options: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    evasion_options: Dict[str, Dict[str, Any]] = field(default_factory=dict)


@dataclass
class MsfSession:
    """Metasploit session information."""
    id: int
    type: MsfSessionType
    tunnel_local: str
    tunnel_peer: str
    via_exploit: str
    via_payload: str
    desc: str
    info: str
    workspace: str
    session_host: str
    session_port: int
    username: str
    uuid: str
    exploit_uuid: str
    routes: List[str] = field(default_factory=list)
    arch: str = ""
    platform: str = ""
    created_at: Optional[datetime] = None
    last_checkin: Optional[datetime] = None


@dataclass
class MsfJob:
    """Metasploit background job."""
    id: int
    name: str
    start_time: datetime
    status: str
    module: str
    workspace: str
    result: Optional[str] = None


@dataclass
class MsfConfig:
    """Metasploit RPC configuration."""
    host: str = "127.0.0.1"
    port: int = 55553
    username: str = "msf"
    password: str = ""
    ssl: bool = True
    ssl_verify: bool = True
    timeout: int = 30
    reconnect_attempts: int = 3
    reconnect_delay: float = 5.0
    
    def __post_init__(self):
        if not self.password:
            raise ValueError("Metasploit RPC password must be provided (no default for security)")
    
    @property
    def uri(self) -> str:
        scheme = "https" if self.ssl else "http"
        return f"{scheme}://{self.host}:{self.port}/api/"


class MetasploitRPC:
    """
    Async Metasploit RPC (msgrpc) client.
    
    Uses MessagePack over HTTP(S) for communication with msgrpc service.
    Provides full module search/execution, session management, and meterpreter interaction.
    """
    
    def __init__(self, config: Optional[MsfConfig] = None):
        self.config = config or MsfConfig()
        self._token: Optional[str] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._connected = False
        self._jobs: Dict[int, MsfJob] = {}
        self._sessions: Dict[int, MsfSession] = {}
        
    async def connect(self) -> bool:
        """Connect to msgrpc and authenticate."""
        if not AIOHTTP_AVAILABLE:
            logger.error("aiohttp not available")
            return False
        
        try:
            # Create SSL context
            ssl_context = None
            if self.config.ssl:
                ssl_context = ssl.create_default_context()
                if not self.config.ssl_verify:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
            
            # Create session with timeout
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
            )
            
            # Authenticate
            auth_result = await self._call("auth.login", self.config.username, self.config.password)
            
            if auth_result.get("result") == "success":
                self._token = auth_result.get("token")
                self._connected = True
                logger.info("Connected to Metasploit RPC", host=self.config.host, port=self.config.port)
                
                # Load existing jobs and sessions
                await self._refresh_jobs()
                await self._refresh_sessions()
                
                return True
            else:
                logger.error("Metasploit authentication failed", error=auth_result.get("error", "Unknown"))
                await self.disconnect()
                return False
                
        except Exception as e:
            logger.error("Failed to connect to Metasploit RPC", error=str(e))
            await self.disconnect()
            return False
    
    async def disconnect(self):
        """Disconnect from msgrpc."""
        if self._session:
            # Logout if token exists
            if self._token:
                try:
                    await self._call("auth.logout")
                except Exception:
                    pass
            
            await self._session.close()
            self._session = None
            self._token = None
            self._connected = False
            logger.info("Disconnected from Metasploit RPC")
    
    async def _call(self, method: str, *args, **kwargs) -> Dict[str, Any]:
        """Make RPC call to msgrpc."""
        if not self._session or not self._connected:
            raise RuntimeError("Not connected to Metasploit RPC")
        
        # Prepare MessagePack request - msgrpc expects array format: [method, token, arg1, arg2, ...]
        params = [method]
        
        if self._token and method != "auth.login":
            params.append(self._token)
        
        params.extend(args)
        
        # Serialize to MessagePack
        packed = msgpack.packb(params, use_bin_type=True)
        
        try:
            async with self._session.post(
                self.config.uri,
                data=packed,
                headers={"Content-Type": "application/msgpack"},
            ) as response:
                if response.status != 200:
                    raise RuntimeError(f"HTTP {response.status}: {await response.text()}")
                
                response_data = await response.read()
                result = msgpack.unpackb(response_data, raw=False)
                return result
                
        except aiohttp.ClientError as e:
            if "timeout" in str(e).lower():
                raise RuntimeError(f"RPC call timeout: {method}")
            
            # Try to reconnect on connection errors
            logger.warning("RPC call failed, attempting reconnect", method=method, error=str(e))
            await self._reconnect()
            raise RuntimeError(f"RPC call failed: {method} - {e}")
    
    async def _reconnect(self) -> bool:
        """Attempt to reconnect to msgrpc."""
        self._connected = False
        
        for attempt in range(self.config.reconnect_attempts):
            logger.info("Attempting reconnect", attempt=attempt + 1)
            await asyncio.sleep(self.config.reconnect_delay)
            
            if await self.connect():
                return True
        
        return False
    
    async def _refresh_jobs(self):
        """Refresh job list from msgrpc."""
        try:
            result = await self._call("job.list")
            jobs_data = result.get("jobs", {})
            
            self._jobs.clear()
            for job_id, job_info in jobs_data.items():
                self._jobs[int(job_id)] = MsfJob(
                    id=int(job_id),
                    name=job_info.get("name", ""),
                    start_time=datetime.fromisoformat(job_info.get("start_time", datetime.now().isoformat())),
                    status=job_info.get("status", "unknown"),
                    module=job_info.get("module", ""),
                    workspace=job_info.get("workspace", "default"),
                )
        except Exception as e:
            logger.warning("Failed to refresh jobs", error=str(e))
    
    async def _refresh_sessions(self):
        """Refresh session list from msgrpc."""
        try:
            result = await self._call("session.list")
            sessions_data = result.get("sessions", {})
            
            self._sessions.clear()
            for session_id, session_info in sessions_data.items():
                self._sessions[int(session_id)] = MsfSession(
                    id=int(session_id),
                    type=MsfSessionType(session_info.get("type", "unknown")),
                    tunnel_local=session_info.get("tunnel_local", ""),
                    tunnel_peer=session_info.get("tunnel_peer", ""),
                    via_exploit=session_info.get("via_exploit", ""),
                    via_payload=session_info.get("via_payload", ""),
                    desc=session_info.get("desc", ""),
                    info=session_info.get("info", ""),
                    workspace=session_info.get("workspace", "default"),
                    session_host=session_info.get("session_host", ""),
                    session_port=session_info.get("session_port", 0),
                    username=session_info.get("username", ""),
                    uuid=session_info.get("uuid", ""),
                    exploit_uuid=session_info.get("exploit_uuid", ""),
                    arch=session_info.get("arch", ""),
                    platform=session_info.get("platform", ""),
                    routes=session_info.get("routes", []),
                )
        except Exception as e:
            logger.warning("Failed to refresh sessions", error=str(e))
    
    # === Module Operations ===
    
    async def module_search(self, query: str) -> List[MsfModule]:
        """Search for modules matching query."""
        result = await self._call("module.search", query)
        modules_data = result.get("modules", [])
        
        modules = []
        for mod in modules_data:
            modules.append(MsfModule(
                fullname=mod.get("fullname", ""),
                name=mod.get("name", ""),
                type=MsfModuleType(mod.get("type", "unknown")),
                description=mod.get("description", ""),
                references=mod.get("references", []),
                authors=mod.get("authors", []),
                platform=mod.get("platform", []),
                arch=mod.get("arch", []),
                targets=mod.get("targets", []),
                options=mod.get("options", {}),
                required_options=mod.get("required", []),
                advanced_options=mod.get("advanced", {}),
                evasion_options=mod.get("evasion", {}),
            ))
        
        return modules
    
    async def module_info(self, module_type: MsfModuleType, module_name: str) -> MsfModule:
        """Get detailed information about a module."""
        result = await self._call("module.info", module_type.value, module_name)
        
        return MsfModule(
            fullname=f"{module_type.value}/{module_name}",
            name=module_name,
            type=module_type,
            description=result.get("description", ""),
            references=result.get("references", []),
            authors=result.get("authors", []),
            platform=result.get("platform", []),
            arch=result.get("arch", []),
            targets=result.get("targets", []),
            options=result.get("options", {}),
            required_options=result.get("required", []),
            advanced_options=result.get("advanced", {}),
            evasion_options=result.get("evasion", {}),
        )
    
    async def module_options(self, module_type: MsfModuleType, module_name: str) -> Dict[str, Any]:
        """Get module options."""
        result = await self._call("module.options", module_type.value, module_name)
        return result.get("options", {})
    
    async def module_execute(
        self,
        module_type: MsfModuleType,
        module_name: str,
        options: Dict[str, Any],
        target: Optional[str] = None,
        payload: Optional[str] = None,
        payload_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute a module with given options.
        
        Returns job ID or session info depending on module type.
        """
        params = [module_type.value, module_name, options]
        
        if target:
            options["RHOSTS"] = target
        if payload:
            options["PAYLOAD"] = payload
        if payload_options:
            for k, v in payload_options.items():
                options[f"PAYLOAD.{k}"] = v
        
        result = await self._call("module.execute", *params)
        return result
    
    async def exploit_execute(
        self,
        exploit_name: str,
        target: str,
        payload: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        payload_options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Execute an exploit module against a target.
        
        Returns job ID if background, or session info if successful.
        """
        options = options or {}
        options["RHOSTS"] = target
        
        return await self.module_execute(
            MsfModuleType.EXPLOIT,
            exploit_name,
            options,
            target=target,
            payload=payload,
            payload_options=payload_options,
        )
    
    async def auxiliary_execute(
        self,
        auxiliary_name: str,
        target: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute an auxiliary module (scanner, etc.)."""
        options = options or {}
        options["RHOSTS"] = target
        
        return await self.module_execute(
            MsfModuleType.AUXILIARY,
            auxiliary_name,
            options,
            target=target,
        )
    
    async def post_execute(
        self,
        post_name: str,
        session_id: int,
        options: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a post-exploitation module on a session."""
        options = options or {}
        options["SESSION"] = session_id
        
        return await self.module_execute(
            MsfModuleType.POST,
            post_name,
            options,
        )
    
    # === Session Management ===
    
    async def session_list(self) -> Dict[int, MsfSession]:
        """Get all active sessions."""
        await self._refresh_sessions()
        return self._sessions.copy()
    
    async def session_get(self, session_id: int) -> Optional[MsfSession]:
        """Get session details."""
        await self._refresh_sessions()
        return self._sessions.get(session_id)
    
    async def session_kill(self, session_id: int) -> bool:
        """Kill/close a session."""
        result = await self._call("session.kill", session_id)
        if result.get("result") == "success":
            self._sessions.pop(session_id, None)
            return True
        return False
    
    async def session_detach(self, session_id: int) -> bool:
        """Detach from a session (keep it alive)."""
        result = await self._call("session.detach", session_id)
        return result.get("result") == "success"
    
    async def session_shell_read(self, session_id: int) -> str:
        """Read from session shell."""
        result = await self._call("session.shell_read", session_id)
        return result.get("data", "")
    
    async def session_shell_write(self, session_id: int, data: str) -> bool:
        """Write to session shell."""
        result = await self._call("session.shell_write", session_id, data)
        return result.get("result") == "success"
    
    async def session_shell_upgrade(self, session_id: int) -> Dict[str, Any]:
        """Upgrade shell to meterpreter."""
        result = await self._call("session.shell_upgrade", session_id)
        return result
    
    async def session_meterpreter_read(self, session_id: int) -> str:
        """Read from meterpreter session."""
        result = await self._call("session.meterpreter_read", session_id)
        return result.get("data", "")
    
    async def session_meterpreter_write(self, session_id: int, data: str) -> bool:
        """Write to meterpreter session."""
        result = await self._call("session.meterpreter_write", session_id, data)
        return result.get("result") == "success"
    
    async def session_meterpreter_run_single(self, session_id: int, command: str) -> Dict[str, Any]:
        """Run a single meterpreter command."""
        result = await self._call("session.meterpreter_run_single", session_id, command)
        return result
    
    async def session_meterpreter_script(self, session_id: int, script: str) -> Dict[str, Any]:
        """Run a meterpreter script."""
        result = await self._call("session.meterpreter_script", session_id, script)
        return result
    
    async def session_compat_modules(self, session_id: int) -> List[str]:
        """Get list of post modules compatible with session."""
        result = await self._call("session.compatible_modules", session_id)
        return result.get("modules", [])
    
    # === Job Management ===
    
    async def job_list(self) -> Dict[int, MsfJob]:
        """List all background jobs."""
        await self._refresh_jobs()
        return self._jobs.copy()
    
    async def job_stop(self, job_id: int) -> bool:
        """Stop a background job."""
        result = await self._call("job.stop", job_id)
        if result.get("result") == "success":
            self._jobs.pop(job_id, None)
            return True
        return False
    
    async def job_info(self, job_id: int) -> Optional[MsfJob]:
        """Get job details."""
        await self._refresh_jobs()
        return self._jobs.get(job_id)
    
    # === Database / Workspace ===
    
    async def db_status(self) -> Dict[str, Any]:
        """Get database connection status."""
        return await self._call("db.status")
    
    async def db_hosts(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get hosts from database."""
        result = await self._call("db.hosts", workspace)
        return result.get("hosts", [])
    
    async def db_services(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get services from database."""
        result = await self._call("db.services", workspace)
        return result.get("services", [])
    
    async def db_vulns(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get vulnerabilities from database."""
        result = await self._call("db.vulns", workspace)
        return result.get("vulns", [])
    
    async def db_notes(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get notes from database."""
        result = await self._call("db.notes", workspace)
        return result.get("notes", [])
    
    async def db_creds(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get credentials from database."""
        result = await self._call("db.creds", workspace)
        return result.get("creds", [])
    
    async def db_loot(self, workspace: str = "default") -> List[Dict[str, Any]]:
        """Get loot from database."""
        result = await self._call("db.loot", workspace)
        return result.get("loot", [])
    
    async def workspace_list(self) -> List[Dict[str, Any]]:
        """List workspaces."""
        result = await self._call("workspace.list")
        return result.get("workspaces", [])
    
    async def workspace_create(self, name: str) -> bool:
        """Create a new workspace."""
        result = await self._call("workspace.create", name)
        return result.get("result") == "success"
    
    async def workspace_delete(self, name: str) -> bool:
        """Delete a workspace."""
        result = await self._call("workspace.delete", name)
        return result.get("result") == "success"
    
    # === Console / Buffer ===
    
    async def console_create(self) -> int:
        """Create a new console."""
        result = await self._call("console.create")
        return result.get("id", 0)
    
    async def console_destroy(self, console_id: int) -> bool:
        """Destroy a console."""
        result = await self._call("console.destroy", console_id)
        return result.get("result") == "success"
    
    async def console_write(self, console_id: int, command: str) -> Dict[str, Any]:
        """Write command to console."""
        return await self._call("console.write", console_id, command)
    
    async def console_read(self, console_id: int) -> Dict[str, Any]:
        """Read console output."""
        return await self._call("console.read", console_id)
    
    async def console_tabs(self, console_id: int, line: str) -> List[str]:
        """Get tab completion for console."""
        result = await self._call("console.tabs", console_id, line)
        return result.get("tabs", [])
    
    # === Utility ===
    
    async def version(self) -> Dict[str, Any]:
        """Get Metasploit version info."""
        return await self._call("version")
    
    async def stats(self) -> Dict[str, Any]:
        """Get framework statistics."""
        return await self._call("stats")
    
    def get_token(self) -> Optional[str]:
        """Get current auth token."""
        return self._token
    
    def is_connected(self) -> bool:
        """Check if connected."""
        return self._connected
    
    async def __aenter__(self):
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()


# Export all public classes
__all__ = [
    "MsfModuleType",
    "MsfSessionType",
    "MsfModule",
    "MsfSession",
    "MsfJob",
    "MsfConfig",
    "MetasploitRPC",
]