"""
Router vulnerability scanner using RouterSploit and Hydra.
"""

import asyncio
import os
import re
import structlog
import tempfile
from typing import Any, Dict, List, Optional

logger = structlog.get_logger(__name__)


class RouterScanner:
    """
    Router vulnerability scanner using RouterSploit and Hydra.
    """

    def __init__(
        self,
        routersploit_path: str = "routersploit",
        hydra_path: str = "hydra",
    ):
        self.routersploit_path = routersploit_path
        self.hydra_path = hydra_path

    async def scan_router(
        self,
        target_ip: str,
        ports: List[int] = None,
        modules: List[str] = None,
    ) -> List[Dict[str, Any]]:
        return []

    async def brute_force_credentials(
        self,
        target_ip: str,
        service: str,
        username_list: List[str],
        password_list: List[str],
        port: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        port = port or self._default_port(service)

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as uf:
            uf.write("\n".join(username_list))
            user_file = uf.name

        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as pf:
            pf.write("\n".join(password_list))
            pass_file = pf.name

        try:
            cmd = [
                self.hydra_path,
                "-L", user_file,
                "-P", pass_file,
                "-t", "4",
                "-f",
                "-v",
                f"{service}://{target_ip}:{port}",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=3600)

            results = []
            stdout_str = stdout.decode()

            for line in stdout_str.split("\n"):
                match = re.search(r"login:\s+(\S+)\s+password:\s+(\S+)", line)
                if match:
                    username, password = match.group(1), match.group(2)
                    results.append({
                        "service": service,
                        "ip": target_ip,
                        "port": port,
                        "username": username,
                        "password": password,
                    })

            return results

        finally:
            os.unlink(user_file)
            os.unlink(pass_file)

    def _default_port(self, service: str) -> int:
        ports = {
            "ssh": 22,
            "http": 80,
            "https": 443,
            "ftp": 21,
            "telnet": 23,
            "smtp": 25,
            "smb": 445,
            "rdp": 3389,
            "mysql": 3306,
            "postgres": 5432,
        }
        return ports.get(service, 80)
