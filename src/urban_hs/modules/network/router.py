"""
Router vulnerability scanner using RouterSploit and Hydra.
"""

import asyncio
import os
import re
import shutil
import tempfile
from typing import Any

import structlog

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
        ports: list[int] = None,
        modules: list[str] = None,
    ) -> list[dict[str, Any]]:
        """Scan a router for known vulnerabilities via RouterSploit.

        Feeds a resource script to the ``routersploit`` console (autopwn by
        default, or the given exploit modules) and parses the vulnerable
        findings. Returns an empty list if RouterSploit is not installed.
        """
        if not shutil.which(self.routersploit_path) and not os.path.exists(self.routersploit_path):
            logger.warning("routersploit not found", path=self.routersploit_path)
            return []

        if modules:
            script_lines: list[str] = []
            for module in modules:
                script_lines += [f"use {module}", f"set target {target_ip}", "run"]
            script_lines.append("exit")
        else:
            script_lines = ["use scanners/autopwn", f"set target {target_ip}", "run", "exit"]
        script = "\n".join(script_lines) + "\n"

        try:
            proc = await asyncio.create_subprocess_exec(
                self.routersploit_path,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(script.encode()), timeout=1800
            )
        except Exception as exc:
            logger.warning("routersploit scan failed", target=target_ip, error=str(exc))
            return []

        return self._parse_autopwn_output(stdout.decode(errors="replace"), target_ip)

    @staticmethod
    def _parse_autopwn_output(output: str, target_ip: str) -> list[dict[str, Any]]:
        """Extract vulnerable findings from RouterSploit autopwn/exploit output."""
        ansi = re.compile(r"\x1b\[[0-9;]*m")
        results: list[dict[str, Any]] = []
        for raw in output.splitlines():
            line = ansi.sub("", raw).strip()
            low = line.lower()
            if "vulnerable" not in low or "not vulnerable" in low or "non-vulnerable" in low:
                continue
            match = re.search(r"((?:exploits|creds)/\S+)", line)
            results.append({
                "ip": target_ip,
                "module": match.group(1) if match else None,
                "vulnerable": True,
                "detail": line,
            })
        return results

    async def brute_force_credentials(
        self,
        target_ip: str,
        service: str,
        username_list: list[str],
        password_list: list[str],
        port: int | None = None,
    ) -> list[dict[str, Any]]:
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
