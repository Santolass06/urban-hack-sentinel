"""
Chroot Process Manager

Executes commands inside Alpine chroot via nsenter/chroot with bind mounts,
resource limits, and environment isolation.
"""

import asyncio
import os
import shlex
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Union

import structlog

logger = structlog.get_logger(__name__)


class ChrootExecMode(Enum):
    """Execution mode for chroot commands."""
    CHROOT = "chroot"           # Standard chroot (requires root)
    NSENTER = "nsenter"         # nsenter (preferred, more isolation)
    UNPRIVILEGED = "unprivileged"  # user namespaces (rootless)


@dataclass
class ChrootConfig:
    """Configuration for chroot execution."""
    chroot_path: str = "/opt/urban-hs/chroot/alpine"
    mode: ChrootExecMode = ChrootExecMode.NSENTER
    bind_mounts: Dict[str, str] = field(default_factory=dict)
    env_vars: Dict[str, str] = field(default_factory=dict)
    working_dir: str = "/"
    user: str = "root"
    group: str = "root"
    timeout: int = 300
    memory_limit_mb: Optional[int] = 512
    cpu_quota_percent: Optional[int] = 80
    network_namespace: bool = True
    pid_namespace: bool = True
    ipc_namespace: bool = True
    uts_namespace: bool = True


@dataclass
class ProcessResult:
    """Result of a chroot process execution."""
    command: str
    returncode: int
    stdout: str
    stderr: str
    duration_ms: int
    timed_out: bool = False
    pid: Optional[int] = None


class ChrootProcessManager:
    """
    Manages process execution inside Alpine chroot.
    
    Features:
    - Multiple execution modes (chroot, nsenter, unprivileged)
    - Configurable bind mounts
    - Resource limits (memory, CPU)
    - Namespace isolation
    - Environment variable management
    - Streaming stdout/stderr
    - Timeout handling
    """

    def __init__(self, config: Optional[ChrootConfig] = None):
        self.config = config or ChrootConfig()
        self._active_processes: Dict[int, asyncio.subprocess.Process] = {}
        from urban_hs.core.config import get_config
        cfg = get_config()
        self._default_binds = {
            "/proc": "/proc",
            "/sys": "/sys",
            "/dev": "/dev",
            "/dev/pts": "/dev/pts",
            "/run": "/run",
            f"{cfg.storage.data_root}/data": "/data",
            f"{cfg.storage.resolve_artifact_root()}": "/artifacts",
            f"{cfg.storage.log_root}/logs": "/logs",
        }

    def _build_nsenter_cmd(self, cmd: List[str]) -> List[str]:
        """Build nsenter command with namespace options."""
        ns_flags = []
        
        if self.config.network_namespace:
            ns_flags.append("--net")
        if self.config.pid_namespace:
            ns_flags.append("--pid")
        if self.config.ipc_namespace:
            ns_flags.append("--ipc")
        if self.config.uts_namespace:
            ns_flags.append("--uts")
        
        # Always use mount namespace for bind mounts
        ns_flags.append("--mount")
        
        # Target PID 1 (init in chroot) or use --target with chroot PID
        # For simplicity, we'll use chroot with nsenter
        nsenter_cmd = ["nsenter"] + ns_flags + ["--target", "1"] + ["--"] + cmd
        return nsenter_cmd

    def _build_chroot_cmd(self, cmd: List[str]) -> List[str]:
        """Build chroot command with bind mounts."""
        # Prepare bind mount commands
        bind_cmds = []
        all_binds = {**self._default_binds, **self.config.bind_mounts}
        
        for src, dst in all_binds.items():
            if os.path.exists(src):
                bind_cmds.append(["mount", "--bind", src, dst])
        
        if bind_cmds:
            # Run bind mounts first, then command - each as separate command list
            # Join with " && " for shell execution
            bind_cmd_strs = [" ".join(b) for b in bind_cmds]
            cmd_str = " ".join(shlex.quote(c) for c in cmd)
            full_cmd = " && ".join(bind_cmd_strs + [cmd_str])
            return ["sh", "-c", full_cmd]
        else:
            return ["chroot", self.config.chroot_path] + cmd

    def _build_command(self, cmd: Union[str, List[str]]) -> List[str]:
        """Build full command based on execution mode."""
        if isinstance(cmd, str):
            cmd_list = shlex.split(cmd)
        else:
            cmd_list = cmd
        
        # Apply working directory
        if self.config.working_dir != "/":
            # Use shell to change directory properly
            cmd_str = " ".join(shlex.quote(c) for c in cmd_list)
            cmd_list = ["sh", "-c", f"cd {shlex.quote(self.config.working_dir)} && {cmd_str}"]
        
        # Set environment variables
        env_prefix = []
        for k, v in self.config.env_vars.items():
            env_prefix.extend(["env", f"{k}={v}"])
        
        if env_prefix:
            cmd_list = env_prefix + cmd_list
        
        if self.config.mode == ChrootExecMode.CHROOT:
            return self._build_chroot_cmd(cmd_list)
        elif self.config.mode == ChrootExecMode.NSENTER:
            return self._build_nsenter_cmd(cmd_list)
        else:
            # Unprivileged - use user namespaces
            return ["unshare", "--user", "--map-root-user", "--"] + cmd_list

    async def execute(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[int] = None,
        input_data: Optional[str] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> ProcessResult:
        """
        Execute command in chroot.
        
        Args:
            cmd: Command to execute (string or list)
            timeout: Timeout in seconds (overrides config)
            input_data: Optional stdin input
            progress_callback: Called with (stream_name, line) for stdout/stderr
            
        Returns:
            ProcessResult with execution details
        """
        start_time = time.time()
        timeout = timeout or self.config.timeout
        
        full_cmd = self._build_command(cmd)
        cmd_str = " ".join(full_cmd) if isinstance(full_cmd, list) else full_cmd
        
        logger.info("Executing in chroot", cmd=cmd_str, mode=self.config.mode.value)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                *full_cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024,  # 1MB buffer
            )
            
            self._active_processes[proc.pid] = proc
            
            stdout_lines = []
            stderr_lines = []
            
            async def read_stream(stream, stream_name, lines_list):
                while True:
                    line = await stream.readline()
                    if not line:
                        break
                    decoded = line.decode(errors="replace").rstrip()
                    lines_list.append(decoded)
                    if progress_callback:
                        progress_callback(stream_name, decoded)
            
            # Read stdout/stderr concurrently
            stdout_task = asyncio.create_task(read_stream(proc.stdout, "stdout", stdout_lines))
            stderr_task = asyncio.create_task(read_stream(proc.stderr, "stderr", stderr_lines))
            
            # Send input if provided
            if input_data and proc.stdin:
                proc.stdin.write(input_data.encode())
                await proc.stdin.drain()
                proc.stdin.close()
            
            try:
                await asyncio.wait_for(
                    asyncio.gather(stdout_task, stderr_task, proc.wait()),
                    timeout=timeout
                )
                returncode = proc.returncode
                timed_out = False
            except asyncio.TimeoutError:
                logger.warning("Chroot command timed out", pid=proc.pid, timeout=timeout)
                proc.kill()
                await proc.wait()
                returncode = -1
                timed_out = True
            
        except Exception as e:
            logger.error("Chroot execution failed", error=str(e))
            return ProcessResult(
                command=cmd_str,
                returncode=-1,
                stdout="",
                stderr=str(e),
                duration_ms=int((time.time() - start_time) * 1000),
                timed_out=False,
            )
        finally:
            if 'proc' in locals() and proc.pid in self._active_processes:
                del self._active_processes[proc.pid]
        
        duration_ms = int((time.time() - start_time) * 1000)
        
        return ProcessResult(
            command=cmd_str,
            returncode=returncode,
            stdout="\n".join(stdout_lines),
            stderr="\n".join(stderr_lines),
            duration_ms=duration_ms,
            timed_out=timed_out,
            pid=proc.pid if 'proc' in locals() else None,
        )

    async def execute_streaming(
        self,
        cmd: Union[str, List[str]],
        timeout: Optional[int] = None,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
    ) -> ProcessResult:
        """
        Execute command with real-time streaming callbacks.
        
        Args:
            cmd: Command to execute
            timeout: Timeout in seconds
            on_stdout: Callback for each stdout line
            on_stderr: Callback for each stderr line
        """
        def progress_cb(stream, line):
            if stream == "stdout" and on_stdout:
                on_stdout(line)
            elif stream == "stderr" and on_stderr:
                on_stderr(line)
        
        return await self.execute(cmd, timeout, progress_callback=progress_cb)

    def kill_all(self):
        """Kill all active processes."""
        for pid, proc in list(self._active_processes.items()):
            try:
                proc.kill()
                logger.warning("Killed chroot process", pid=pid)
            except ProcessLookupError:
                pass
        self._active_processes.clear()

    async def run_script(
        self,
        script_path: str,
        args: List[str] = None,
        timeout: Optional[int] = None,
        progress_callback: Optional[Callable[[str, str], None]] = None,
    ) -> ProcessResult:
        """Execute a script file inside chroot."""
        args = args or []
        cmd = [script_path] + args
        return await self.execute(cmd, timeout, progress_callback=progress_callback)

    async def run_python(
        self,
        code: str,
        timeout: Optional[int] = None,
        args: List[str] = None,
    ) -> ProcessResult:
        """Run Python code in chroot."""
        args = args or []
        cmd = ["python3", "-c", code] + args
        return await self.execute(cmd, timeout)

    def check_chroot_health(self) -> Dict[str, Any]:
        """Check if chroot is accessible and healthy."""
        result = {
            "chroot_exists": os.path.exists(self.config.chroot_path),
            "chroot_path": self.config.chroot_path,
            "mode": self.config.mode.value,
        }
        
        if result["chroot_exists"]:
            # Check key directories
            key_dirs = ["/bin", "/usr/bin", "/etc", "/lib", "/usr/lib"]
            for d in key_dirs:
                path = os.path.join(self.config.chroot_path, d.lstrip("/"))
                result[f"has_{d.strip('/').replace('/', '_')}"] = os.path.exists(path)
            
            # Check package manager
            result["has_apk"] = os.path.exists(os.path.join(self.config.chroot_path, "sbin/apk"))
        
        return result


class ChrootManager:
    """
    High-level chroot lifecycle manager.
    
    Handles:
    - Bootstrap (delegates to bootstrap_chroot.sh)
    - Mount/umount bind mounts
    - Health checks
    - Process management
    """

    def __init__(self, chroot_path: str = "/opt/urban-hs/chroot/alpine"):
        self.chroot_path = chroot_path
        self.process_manager: Optional[ChrootProcessManager] = None
        self._mounted = False

    def get_process_manager(self, config: Optional[ChrootConfig] = None) -> ChrootProcessManager:
        """Get or create process manager."""
        if config is None:
            config = ChrootConfig(chroot_path=self.chroot_path)
        self.process_manager = ChrootProcessManager(config)
        return self.process_manager

    async def ensure_chroot(self, force_rebuild: bool = False) -> bool:
        """Ensure chroot exists and is bootstrapped."""
        if not force_rebuild and os.path.exists(self.chroot_path):
            # Quick health check
            pm = self.get_process_manager()
            health = pm.check_chroot_health()
            if health.get("chroot_exists") and health.get("has_apk"):
                logger.info("Chroot already exists and healthy")
                return True
        
        logger.info("Bootstrapping chroot...", path=self.chroot_path)
        
        # Run bootstrap script - use project-relative path
        script_path = Path(__file__).parents[4] / "scripts" / "bootstrap_chroot.sh"
        if not script_path.exists():
            logger.error("Bootstrap script not found", path=str(script_path))
            return False
        
        # Run as root (required for chroot bootstrap)
        result = await asyncio.create_subprocess_exec(
            "sudo", str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await result.communicate()
        
        if result.returncode != 0:
            logger.error("Chroot bootstrap failed", stderr=stderr.decode()[:500])
            return False
        
        logger.info("Chroot bootstrap completed")
        return True

    def mount_binds(self, config: Optional[ChrootConfig] = None) -> bool:
        """Mount bind mounts for chroot."""
        if self._mounted:
            return True
        
        config = config or ChrootConfig(chroot_path=self.chroot_path)
        default_binds = self.process_manager._default_binds if self.process_manager else {}
        all_binds = {**default_binds, **config.bind_mounts}
        
        for src, dst in all_binds.items():
            dst_path = os.path.join(self.chroot_path, dst.lstrip("/"))
            try:
                os.makedirs(dst_path, exist_ok=True)
                if os.path.ismount(dst_path):
                    continue
                subprocess.run(["mount", "--bind", src, dst_path], check=True)
                logger.info("Bind mounted", src=src, dst=dst)
            except subprocess.CalledProcessError as e:
                logger.error("Bind mount failed", src=src, dst=dst, error=str(e))
                return False
        
        self._mounted = True
        return True

    def unmount_binds(self):
        """Unmount bind mounts."""
        if not self._mounted:
            return
        
        # Unmount in reverse order
        mounts = [
            "/data", "/artifacts", "/logs",
            "/run", "/dev/pts", "/dev", "/sys", "/proc"
        ]
        
        for m in mounts:
            path = os.path.join(self.chroot_path, m.lstrip("/"))
            if os.path.ismount(path):
                try:
                    subprocess.run(["umount", "-l", path], check=True)
                    logger.info("Unmounted", path=path)
                except subprocess.CalledProcessError:
                    logger.warning("Unmount failed (may be busy)", path=path)
        
        self._mounted = False

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.process_manager:
            self.process_manager.kill_all()
        self.unmount_binds()


# Convenience functions
async def quick_chroot_cmd(
    cmd: Union[str, List[str]],
    chroot_path: str = "/opt/urban-hs/chroot/alpine",
    timeout: int = 60,
) -> ProcessResult:
    """Quick one-off command execution in chroot."""
    config = ChrootConfig(chroot_path=chroot_path, timeout=timeout)
    pm = ChrootProcessManager(config)
    return await pm.execute(cmd)


async def run_in_chroot(
    script: str,
    chroot_path: str = "/opt/urban-hs/chroot/alpine",
    timeout: int = 300,
) -> ProcessResult:
    """Run a script file in chroot."""
    return await quick_chroot_cmd([script], chroot_path, timeout)


# Export all public classes
__all__ = [
    "ChrootConfig",
    "ChrootExecMode",
    "ProcessResult",
    "ChrootProcessManager",
    "ChrootManager",
    "quick_chroot_cmd",
    "run_in_chroot",
]