"""
Nuclei vulnerability scanner wrapper.
"""

import asyncio
import json
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

import structlog

from urban_hs.modules.network.types import Severity, Vulnerability

logger = structlog.get_logger(__name__)


class NucleiRunner:
    """
    Nuclei vulnerability scanner wrapper.

    Runs nuclei templates and parses JSONL output.
    Supports template filtering by tags, severity, author, etc.
    """

    def __init__(
        self,
        nuclei_path: str = "nuclei",
        templates_dir: Optional[str] = None,
        severity_levels: List[str] = None,
        tags: List[str] = None,
        rate_limit: int = 150,
        timeout: int = 300,
    ):
        self.nuclei_path = nuclei_path
        self.templates_dir = templates_dir
        self.severity_levels = severity_levels or ["critical", "high", "medium", "low"]
        self.tags = tags or []
        self.rate_limit = rate_limit
        self.timeout = timeout

    async def scan(
        self,
        targets: Union[str, List[str]],
        template_dirs: List[str] = None,
        exclude_tags: List[str] = None,
        extra_args: List[str] = None,
    ) -> List[Vulnerability]:
        if isinstance(targets, str):
            targets = [targets]

        cmd = [self.nuclei_path]
        cmd.extend(["-target", ",".join(targets)])

        if template_dirs:
            for d in template_dirs:
                cmd.extend(["-t", d])

        if self.severity_levels:
            cmd.extend(["-severity", ",".join(self.severity_levels)])

        if self.tags:
            cmd.extend(["-tags", ",".join(self.tags)])
        if exclude_tags:
            for tag in exclude_tags:
                cmd.extend(["-exclude-tags", tag])

        cmd.extend(["-rate-limit", str(self.rate_limit)])
        cmd.extend(["-jsonl", "-"])

        if extra_args:
            cmd.extend(extra_args)

        logger.info("Starting nuclei scan", cmd=" ".join(cmd), targets=targets)

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            vulnerabilities = []

            async for line in proc.stdout:
                line = line.decode().strip()
                if not line:
                    continue
                try:
                    vuln_data = json.loads(line)
                    vuln = self._parse_nuclei_finding(vuln_data)
                    if vuln:
                        vulnerabilities.append(vuln)
                except json.JSONDecodeError:
                    continue

            await asyncio.wait_for(proc.wait(), timeout=300)

            logger.info("Nuclei scan completed", vulns_found=len(vulnerabilities))
            return vulnerabilities

        except asyncio.TimeoutError:
            logger.error("Nuclei scan timeout")
            return []
        except Exception as e:
            logger.error("Nuclei scan error", error=str(e))
            return []

    def _parse_nuclei_finding(self, data: Dict[str, Any]) -> Optional[Vulnerability]:
        try:
            info = data.get("info", {})
            severity_str = info.get("severity", "unknown").lower()
            severity_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
                "info": Severity.INFO,
            }

            cvss = None
            cvss_str = info.get("classification", {}).get("cvss-metrics", "")
            if cvss_str:
                try:
                    cvss = float(cvss_str.split("/")[-1])
                except (ValueError, IndexError):
                    pass

            return Vulnerability(
                id=data.get("template-id", data.get("template", "")),
                cve_id=info.get("cve", [None])[0] if info.get("cve") else None,
                name=info.get("name", ""),
                severity=severity_map.get(severity_str, Severity.UNKNOWN),
                cvss_score=cvss,
                description=info.get("description", ""),
                target_ip=self._extract_target_ip(data.get("matched-at", "")),
                exploit_available=info.get("exploit", False),
                nuclei_template=data.get("template-id", data.get("template", "")),
                status="identified",
                references=info.get("reference", []),
                tags=info.get("tags", []),
            )
        except Exception as e:
            logger.warning("Failed to parse nuclei finding", error=str(e))
            return None

    def _extract_target_ip(self, matched_at: str) -> str:
        try:
            parsed = urlparse(matched_at)
            return parsed.hostname or ""
        except Exception:
            return ""
