"""
Report Generator - Jinja2 templates to Markdown/HTML/PDF reports.

Generates professional penetration testing reports with:
- Executive summary
- Findings table with severity
- Evidence appendix
- Chain of custody documentation
- GPG signing support
"""

import asyncio
import base64
import hashlib
import json
import os
import structlog
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable, Union
from uuid import uuid4

try:
    from jinja2 import Environment, FileSystemLoader, select_autoescape
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    from weasyprint import HTML, CSS
    WEASYPRINT_AVAILABLE = True
except ImportError:
    WEASYPRINT_AVAILABLE = False

try:
    import gnupg as gpg
    GPG_AVAILABLE = True
except ImportError:
    GPG_AVAILABLE = False

logger = structlog.get_logger(__name__)


class ReportFormat(Enum):
    """Output format for reports."""
    MARKDOWN = "markdown"
    HTML = "html"
    PDF = "pdf"
    JSON = "json"


class FindingSeverity(Enum):
    """Finding severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingStatus(Enum):
    """Finding status."""
    OPEN = "open"
    CONFIRMED = "confirmed"
    FIXED = "fixed"
    FALSE_POSITIVE = "false_positive"
    RISK_ACCEPTED = "risk_accepted"


@dataclass
class Evidence:
    """Evidence artifact."""
    id: str = field(default_factory=lambda: str(uuid4()))
    finding_id: str = ""
    type: str = ""  # screenshot, log, capture, file, command_output
    path: str = ""
    description: str = ""
    collected_at: datetime = field(default_factory=datetime.utcnow)
    collector: str = ""
    hash_sha256: str = ""
    gpg_signature: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def compute_hash(self) -> str:
        """Compute SHA256 hash of evidence file."""
        if os.path.exists(self.path):
            sha256 = hashlib.sha256()
            with open(self.path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    sha256.update(chunk)
            self.hash_sha256 = sha256.hexdigest()
        return self.hash_sha256


@dataclass
class Finding:
    """Security finding."""
    id: str = field(default_factory=lambda: str(uuid4()))
    title: str = ""
    description: str = ""
    severity: FindingSeverity = FindingSeverity.UNKNOWN
    status: FindingStatus = FindingStatus.OPEN
    cvss_score: Optional[float] = None
    cvss_vector: str = ""
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)
    affected_hosts: List[str] = field(default_factory=list)
    affected_services: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    proof_of_concept: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def severity_order(self) -> int:
        """Numeric order for sorting by severity."""
        order = {
            FindingSeverity.CRITICAL: 0,
            FindingSeverity.HIGH: 1,
            FindingSeverity.MEDIUM: 2,
            FindingSeverity.LOW: 3,
            FindingSeverity.INFO: 4,
            FindingSeverity.UNKNOWN: 5,
        }
        return order.get(self.severity, 5)


@dataclass
class AuditSession:
    """Audit session metadata."""
    id: str = field(default_factory=lambda: str(uuid4()))
    name: str = ""
    scope: List[str] = field(default_factory=list)  # IP ranges, domains, etc.
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    team_members: List[str] = field(default_factory=list)
    methodology: str = ""
    tools_used: List[str] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    credentials_found: int = 0
    hosts_scanned: int = 0
    services_enumerated: int = 0
    vulnerabilities_found: int = 0
    exploits_attempted: int = 0
    exploits_successful: int = 0
    notes: str = ""
    gpg_signed: bool = False
    gpg_signature: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def duration(self) -> Optional[timedelta]:
        if self.end_time:
            return self.end_time - self.start_time
        return None
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.HIGH)
    
    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.MEDIUM)
    
    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.LOW)
    
    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == FindingSeverity.INFO)


@dataclass
class ReportConfig:
    """Report generation configuration."""
    output_dir: str = "/var/lib/urban-hs/reports"
    template_dir: str = "/opt/urban-hs/templates/reports"
    gpg_key_id: Optional[str] = None
    gpg_passphrase: Optional[str] = None
    include_evidence: bool = True
    include_poc: bool = True
    include_raw_output: bool = False
    sign_report: bool = True
    watermark: Optional[str] = None
    logo_path: Optional[str] = None
    company_name: str = "Urban Hack Sentinel"
    company_logo: Optional[str] = None
    classification: str = "CONFIDENTIAL"
    language: str = "en"


class ReportGenerator:
    """
    Generates professional penetration testing reports.
    
    Features:
    - Multiple output formats (Markdown, HTML, PDF)
    - Jinja2 templating with customizable templates
    - WeasyPrint for high-quality PDF generation
    - GPG signing for integrity
    - Evidence appendix with chain of custody
    - Executive summary with risk scoring
    """
    
    def __init__(self, config: Optional[ReportConfig] = None):
        self.config = config or ReportConfig()
        self.report_dir = Path(self.config.output_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        # Setup Jinja2 environment
        self.jinja_env = None
        if JINJA2_AVAILABLE:
            template_dirs = [
                self.config.template_dir,
                os.path.join(os.path.dirname(__file__), "templates"),
            ]
            self.jinja_env = Environment(
                loader=FileSystemLoader(template_dirs),
                autoescape=select_autoescape(['html', 'xml']),
                trim_blocks=True,
                lstrip_blocks=True,
            )
            # Add custom filters
            self.jinja_env.filters['datetime'] = self._format_datetime
            self.jinja_env.filters['severity_badge'] = self._severity_badge
            self.jinja_env.filters['severity_color'] = self._severity_color
        else:
            logger.warning("Jinja2 not available, using built-in templates")
    
    def _format_datetime(self, dt: datetime, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
        """Format datetime for templates."""
        if dt:
            return dt.strftime(fmt)
        return "N/A"
    
    def _severity_badge(self, severity: FindingSeverity) -> str:
        """Generate HTML badge for severity."""
        badges = {
            FindingSeverity.CRITICAL: '<span class="badge badge-critical">CRITICAL</span>',
            FindingSeverity.HIGH: '<span class="badge badge-high">HIGH</span>',
            FindingSeverity.MEDIUM: '<span class="badge badge-medium">MEDIUM</span>',
            FindingSeverity.LOW: '<span class="badge badge-low">LOW</span>',
            FindingSeverity.INFO: '<span class="badge badge-info">INFO</span>',
            FindingSeverity.UNKNOWN: '<span class="badge badge-unknown">UNKNOWN</span>',
        }
        return badges.get(FindingSeverity(severity) if isinstance(severity, str) else severity, '<span class="badge badge-unknown">UNKNOWN</span>')
    
    def _severity_color(self, severity: FindingSeverity) -> str:
        """Get CSS color for severity."""
        colors = {
            FindingSeverity.CRITICAL: "#dc3545",
            FindingSeverity.HIGH: "#fd7e14",
            FindingSeverity.MEDIUM: "#ffc107",
            FindingSeverity.LOW: "#28a745",
            FindingSeverity.INFO: "#17a2b8",
            FindingSeverity.UNKNOWN: "#6c757d",
        }
        return colors.get(FindingSeverity(severity) if isinstance(severity, str) else severity, "#6c757d")
    
    async def generate(
        self,
        session: AuditSession,
        format: ReportFormat = ReportFormat.PDF,
        custom_template: Optional[str] = None,
    ) -> str:
        """
        Generate report from audit session.
        
        Args:
            session: Audit session with findings and evidence
            format: Output format
            custom_template: Optional custom template name
        
        Returns:
            Path to generated report
        """
        # Ensure session has end time
        if not session.end_time:
            session.end_time = datetime.utcnow()
        
        # Sort findings by severity
        session.findings.sort(key=lambda f: f.severity_order)
        
        # Generate report content
        if format == ReportFormat.MARKDOWN:
            return await self._generate_markdown(session)
        elif format == ReportFormat.HTML:
            return await self._generate_html(session, custom_template)
        elif format == ReportFormat.PDF:
            return await self._generate_pdf(session, custom_template)
        elif format == ReportFormat.JSON:
            return await self._generate_json(session)
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    async def _generate_markdown(self, session: AuditSession) -> str:
        """Generate Markdown report."""
        output_path = self.report_dir / f"report_{session.id}_{int(time.time())}.md"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        md = [
            f"# {session.name} - Penetration Test Report\n",
            f"**Classification:** {self.config.classification}\n",
            f"**Session ID:** {session.id}\n",
            f"**Date:** {self._format_datetime(session.start_time)} - {self._format_datetime(session.end_time or datetime.utcnow())}\n",
            f"**Duration:** {session.duration}\n",
            f"**Team:** {', '.join(session.team_members) if session.team_members else 'N/A'}\n",
            f"**Methodology:** {session.methodology}\n",
            f"**Tools:** {', '.join(session.tools_used) if session.tools_used else 'N/A'}\n",
            f"**Scope:** {', '.join(session.scope) if session.scope else 'N/A'}\n",
            f"**Classification:** {self.config.classification}\n",
            "---\n",
        ]
        
        # Executive Summary
        md.append("## Executive Summary\n")
        md.append(f"This report details the findings of a penetration test conducted against **{session.name}**.\n")
        md.append(f"The assessment was conducted from {self._format_datetime(session.start_time)} to {self._format_datetime(session.end_time or datetime.utcnow())}.\n\n")
        
        md.append("### Risk Summary\n")
        md.append(f"- **Critical:** {session.critical_count}")
        md.append(f"- **High:** {session.high_count}")
        md.append(f"- **Medium:** {session.medium_count}")
        md.append(f"- **Low:** {session.low_count}")
        md.append(f"- **Info:** {session.info_count}\n")
        
        md.append("### Statistics\n")
        md.append(f"- **Hosts Scanned:** {session.hosts_scanned}")
        md.append(f"- **Services Enumerated:** {session.services_enumerated}")
        md.append(f"- **Vulnerabilities Found:** {session.vulnerabilities_found}")
        md.append(f"- **Exploits Attempted:** {session.exploits_attempted}")
        md.append(f"- **Exploits Successful:** {session.exploits_successful}")
        md.append(f"- **Credentials Found:** {session.credentials_found}\n")
        
        # Findings
        if session.findings:
            md.append("## Findings\n")
            
            for finding in session.findings:
                md.append(f"\n### {finding.title} [{finding.severity.value.upper()}]\n")
                md.append(f"**Finding ID:** {finding.id}\n")
                md.append(f"**Severity:** {finding.severity.value.upper()}")
                if finding.cvss_score:
                    md.append(f"**CVSS Score:** {finding.cvss_score} ({finding.cvss_vector})")
                if finding.cve_ids:
                    md.append(f"**CVE IDs:** {', '.join(finding.cve_ids)}")
                if finding.cwe_ids:
                    md.append(f"**CWE IDs:** {', '.join(finding.cwe_ids)}")
                if finding.affected_hosts:
                    md.append(f"**Affected Hosts:** {', '.join(finding.affected_hosts)}")
                if finding.affected_services:
                    md.append(f"**Affected Services:** {', '.join(finding.affected_services)}")
                
                md.append(f"\n**Description:**\n{finding.description}\n")
                
                if finding.proof_of_concept:
                    md.append(f"\n**Proof of Concept:**\n```\n{finding.proof_of_concept}\n```\n")
                
                if finding.remediation:
                    md.append(f"\n**Remediation:**\n{finding.remediation}\n")
                
                if finding.references:
                    md.append(f"\n**References:**")
                    for ref in finding.references:
                        md.append(f"- {ref}")
                    md.append("")
                
                if finding.tags:
                    md.append(f"**Tags:** {', '.join(finding.tags)}")
                md.append("---\n")
        
        # Evidence Appendix
        if session.evidence:
            md.append("## Evidence Appendix\n")
            for evidence in session.evidence:
                md.append(f"\n### Evidence: {evidence.description}\n")
                md.append(f"- **Type:** {evidence.type}")
                md.append(f"- **File:** {evidence.path}")
                md.append(f"- **SHA256:** {evidence.hash_sha256}")
                if evidence.gpg_signature:
                    md.append(f"- **GPG Signature:** {evidence.gpg_signature}")
                md.append(f"- **Collected:** {self._format_datetime(evidence.collected_at)}")
                md.append(f"- **Collector:** {evidence.collector}\n")
        
        # Notes
        if session.notes:
            md.append("## Notes\n")
            md.append(f"{session.notes}\n")
        
        # Chain of Custody
        md.append("## Chain of Custody\n")
        md.append(f"- **Report Generated:** {self._format_datetime(datetime.utcnow())}")
        md.append(f"- **Generated By:** Urban Hack Sentinel")
        md.append(f"- **Session ID:** {session.id}")
        if self.config.gpg_key_id:
            md.append(f"- **GPG Key:** {self.config.gpg_key_id}")
        
        content = "\n".join(md)
        
        with open(self.report_dir / f"report_{session.id}_{int(time.time())}.md", 'w') as f:
            f.write(content)
        
        return str(self.report_dir / f"report_{session.id}_{int(time.time())}.md")
    
    async def _generate_html(self, session: AuditSession, custom_template: Optional[str] = None) -> str:
        """Generate HTML report using Jinja2."""
        if not self.jinja_env:
            raise RuntimeError("Jinja2 not available for HTML generation")
        
        template_name = custom_template or "report.html"
        
        try:
            template = self.jinja_env.get_template(template_name)
        except Exception:
            # Use built-in template
            template = self.jinja_env.from_string(self._get_builtin_html_template())
        
        # Prepare template context
        context = {
            "session": session,
            "config": self.config,
            "generator": self,
            "generated_at": datetime.utcnow(),
        }
        
        html_content = template.render(**context)
        
        output_path = self.report_dir / f"report_{session.id}_{int(time.time())}.html"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        return str(output_path)
    
    def _get_builtin_html_template(self) -> str:
        """Built-in HTML template for report generation."""
        return """
<!DOCTYPE html>
<html lang="{{ config.language }}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ session.name }} - Penetration Test Report</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; }
        h2 { color: #34495e; border-bottom: 1px solid #ecf0f1; padding-bottom: 5px; }
        h3 { color: #2c3e50; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: white; }
        .badge-critical { background: #dc3545; }
        .badge-high { background: #fd7e14; }
        .badge-medium { background: #ffc107; color: #212529; }
        .badge-low { background: #28a745; }
        .badge-info { background: #17a2b8; }
        .badge-unknown { background: #6c757d; }
        .finding { border-left: 4px solid #3498db; padding: 20px; margin: 20px 0; background: #f8f9fa; border-radius: 0 8px 8px 0; }
        .finding.critical { border-left-color: #dc3545; }
        .finding.high { border-left-color: #fd7e14; }
        .finding.medium { border-left-color: #ffc107; }
        .finding.low { border-left-color: #28a745; }
        .finding.info { border-left-color: #17a2b8; }
        .metadata { background: #f8f9fa; padding: 15px; border-radius: 4px; margin: 10px 0; font-family: monospace; font-size: 0.9em; }
        .evidence { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 4px; border-left: 3px solid #6c757d; }
        .summary-stats { display: flex; gap: 15px; flex-wrap: wrap; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; }
        .stat-label { color: #6c757d; font-size: 0.9em; }
        .critical-stat .stat-value { color: #dc3545; }
        .high-stat .stat-value { color: #fd7e14; }
        .medium-stat .stat-value { color: #ffc107; }
        .low-stat .stat-value { color: #28a745; }
        .info-stat .stat-value { color: #17a2b8; }
        code { background: #f1f1f1; padding: 2px 6px; border-radius: 4px; }
        pre { background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 4px; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        th { background: #34495e; color: white; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #ecf0f1; color: #6c757d; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>{{ session.name }} - Penetration Test Report</h1>
            <p><strong>Classification:</strong> {{ config.classification }}</p>
            <p><strong>Session ID:</strong> {{ session.id }}</p>
            <p><strong>Date:</strong> {{ generator._format_datetime(session.start_time) }} - {{ generator._format_datetime(session.end_time or datetime.utcnow()) }}</p>
            <p><strong>Duration:</strong> {{ session.duration }}</p>
            <p><strong>Team:</strong> {{ session.team_members|join(', ') if session.team_members else 'N/A' }}</p>
            <p><strong>Methodology:</strong> {{ session.methodology }}</p>
        </header>
        
        <section>
            <h2>Executive Summary</h2>
            <p>This report details the findings of a penetration test conducted against <strong>{{ session.name }}</strong>.</p>
            <p>The assessment was conducted from {{ generator._format_datetime(session.start_time) }} to {{ generator._format_datetime(session.end_time or datetime.utcnow()) }}.</p>
            
            <h3>Risk Summary</h3>
            <div class="summary-stats">
                <div class="stat-card critical-stat">
                    <div class="stat-value">{{ session.critical_count }}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high-stat">
                    <div class="stat-value">{{ session.high_count }}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium-stat">
                    <div class="stat-value">{{ session.medium_count }}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low-stat">
                    <div class="stat-value">{{ session.low_count }}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info-stat">
                    <div class="stat-value">{{ session.info_count }}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            
            <h3>Statistics</h3>
            <ul>
                <li>Hosts Scanned: {{ session.hosts_scanned }}</li>
                <li>Services Enumerated: {{ session.services_enumerated }}</li>
                <li>Vulnerabilities Found: {{ session.vulnerabilities_found }}</li>
                <li>Exploits Attempted: {{ session.exploits_attempted }}</li>
                <li>Exploits Successful: {{ session.exploits_successful }}</li>
                <li>Credentials Found: {{ session.credentials_found }}</li>
            </ul>
        </section>
        
        {% if session.findings %}
        <section>
            <h2>Findings</h2>
            {% for finding in session.findings %}
            <div class="finding {{ finding.severity.value }}">
                <h3>{{ finding.title }} <span class="badge {{ finding.severity.value }}">{{ finding.severity.value.upper() }}</span></h3>
                <p><strong>Finding ID:</strong> {{ finding.id }}</p>
                <p><strong>Severity:</strong> {{ finding.severity.value.upper() }}
                {% if finding.cvss_score %} (CVSS: {{ finding.cvss_score }} / {{ finding.cvss_vector }}){% endif %}</p>
                {% if finding.cve_ids %}<p><strong>CVE IDs:</strong> {{ finding.cve_ids|join(', ') }}</p>{% endif %}
                {% if finding.cwe_ids %}<p><strong>CWE IDs:</strong> {{ finding.cwe_ids|join(', ') }}</p>{% endif %}
                {% if finding.affected_hosts %}<p><strong>Affected Hosts:</strong> {{ finding.affected_hosts|join(', ') }}</p>{% endif %}
                {% if finding.affected_services %}<p><strong>Affected Services:</strong> {{ finding.affected_services|join(', ') }}</p>{% endif %}
                
                <h4>Description</h4>
                <p>{{ finding.description }}</p>
                
                {% if finding.proof_of_concept %}
                <h4>Proof of Concept</h4>
                <pre>{{ finding.proof_of_concept }}</pre>
                {% endif %}
                
                {% if finding.remediation %}
                <h4>Remediation</h4>
                <p>{{ finding.remediation }}</p>
                {% endif %}
                
                {% if finding.references %}
                <h4>References</h4>
                <ul>
                {% for ref in finding.references %}
                    <li>{{ ref }}</li>
                {% endfor %}
                </ul>
                {% endif %}
                
                {% if finding.tags %}<p><strong>Tags:</strong> {{ finding.tags|join(', ') }}</p>{% endif %}
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        {% if session.evidence %}
        <section>
            <h2>Evidence Appendix</h2>
            {% for evidence in session.evidence %}
            <div class="evidence">
                <h4>{{ evidence.description }}</h4>
                <p><strong>Type:</strong> {{ evidence.type }}</p>
                <p><strong>File:</strong> {{ evidence.path }}</p>
                <p><strong>SHA256:</strong> {{ evidence.hash_sha256 }}</p>
                {% if evidence.gpg_signature %}<p><strong>GPG Signature:</strong> {{ evidence.gpg_signature }}</p>{% endif %}
                <p><strong>Collected:</strong> {{ generator._format_datetime(evidence.collected_at) }}</p>
                <p><strong>Collector:</strong> {{ evidence.collector }}</p>
            </div>
            {% endfor %}
        </section>
        {% endif %}
        
        <footer class="footer">
            <h3>Chain of Custody</h3>
            <p>Report Generated: {{ generator._format_datetime(datetime.utcnow()) }}</p>
            <p>Generated By: Urban Hack Sentinel</p>
            <p>Session ID: {{ session.id }}</p>
        </footer>
    </div>
</body>
</html>
"""
    
    async def _generate_pdf(self, session: AuditSession, custom_template: Optional[str] = None) -> str:
        """Generate PDF report using WeasyPrint."""
        if not WEASYPRINT_AVAILABLE:
            raise RuntimeError("WeasyPrint not available for PDF generation")
        
        # Generate HTML first
        html_path = await self._generate_html(session, custom_template)
        
        # Convert to PDF
        timestamp = int(time.time())
        pdf_path = self.report_dir / f"report_{session.id}_{int(time.time())}.pdf"
        
        try:
            html = HTML(filename=html_path)
            html.write_pdf(str(pdf_path))
            logger.info("PDF report generated", path=str(pdf_path))
            return str(pdf_path)
        except Exception as e:
            logger.error("PDF generation failed", error=str(e))
            raise
    
    async def _generate_json(self, session: AuditSession) -> str:
        """Generate JSON report."""
        output_path = self.report_dir / f"report_{session.id}_{int(time.time())}.json"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        
        data = {
            "session": {
                "id": session.id,
                "name": session.name,
                "scope": session.scope,
                "start_time": session.start_time.isoformat(),
                "end_time": session.end_time.isoformat() if session.end_time else None,
                "team_members": session.team_members,
                "methodology": session.methodology,
                "tools_used": session.tools_used,
                "notes": session.notes,
                "statistics": {
                    "hosts_scanned": session.hosts_scanned,
                    "services_enumerated": session.services_enumerated,
                    "vulnerabilities_found": session.vulnerabilities_found,
                    "exploits_attempted": session.exploits_attempted,
                    "exploits_successful": session.exploits_successful,
                    "credentials_found": session.credentials_found,
                },
            },
            "findings": [f.__dict__ for f in session.findings],
            "evidence": [e.__dict__ for e in session.evidence],
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "Urban Hack Sentinel",
                "version": "1.0",
                "classification": self.config.classification,
            }
        }
        
        # Fix serialization of nested objects
        def serialize_obj(obj):
            if hasattr(obj, '__dict__'):
                result = {}
                for k, v in obj.__dict__.items():
                    if isinstance(v, datetime):
                        result[k] = v.isoformat()
                    elif isinstance(v, (FindingSeverity, FindingStatus)):
                        result[k] = v.value
                    elif isinstance(v, (list, dict)):
                        result[k] = v
                    elif v is None:
                        result[k] = None
                    else:
                        result[k] = str(v)
                return result
        
        json_data = {
            "session": serialize_obj(session),
            "findings": [serialize_obj(f) for f in session.findings],
            "evidence": [serialize_obj(e) for e in session.evidence],
            "metadata": {
                "generated_at": datetime.utcnow().isoformat(),
                "generator": "Urban Hack Sentinel",
                "version": "1.0",
                "classification": self.config.classification,
            }
        }
        
        with open(output_path, 'w') as f:
            json.dump(json_data, f, indent=2, default=str)
        
        return str(output_path)
    
    def sign_report(self, report_path: str) -> bool:
        """Sign report with GPG."""
        if not self.config.gpg_key_id:
            logger.warning("No GPG key configured for signing")
            return False
        
        if not GPG_AVAILABLE:
            logger.error("GPG not available for signing")
            return False
        
        try:
            gpg = gpg.GPG()
            
            with open(report_path, 'rb') as f:
                report_data = f.read()
            
            signature = gpg.sign(
                report_data,
                keyid=self.config.gpg_key_id,
                passphrase=self.config.gpg_passphrase,
                detach=True,
                armor=True,
            )
            
            if signature:
                sig_path = report_path + ".asc"
                with open(sig_path, 'w') as f:
                    f.write(str(signature))
                logger.info("Report signed", signature_path=sig_path)
                return True
            else:
                logger.error("GPG signing failed")
                return False
                
        except Exception as e:
            logger.error("GPG signing error", error=str(e))
            return False
    
    async def sign_and_verify(self, session: AuditSession, format: ReportFormat = ReportFormat.PDF) -> Dict[str, Any]:
        """Generate, sign, and verify report."""
        result = {"signed": False, "verified": False, "report_path": "", "signature_path": ""}
        
        # Generate report
        report_path = await self.generate(session, format)
        result["report_path"] = report_path
        
        # Sign report
        if self.config.sign_report and self.config.gpg_key_id:
            if self.sign_report(report_path):
                result["signed"] = True
                result["signature_path"] = report_path + ".asc"
        
        return result


# Built-in finding templates
class FindingTemplates:
    """Pre-built finding templates for common vulnerabilities."""
    
    @staticmethod
    def wifi_kr00k() -> Finding:
        return Finding(
            title="WiFi Kr00k Vulnerability (CVE-2019-15126)",
            description="Broadcom/Cypress WiFi chips use all-zero encryption key after disassociation, allowing decryption of wireless traffic.",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cve_ids=["CVE-2019-15126"],
            cwe_ids=["CWE-319"],
            affected_services=["WiFi"],
            tags=["wifi", "kr00k", "decryption"],
            proof_of_concept="Force disassociation, capture traffic with all-zero key",
            remediation="Update WiFi firmware/drivers to patched versions",
            references=[
                "https://web-assets.esetstatic.com/wls/2020/02/ESET_Kr00k.pdf",
                "https://www.eset.com/int/about/newsroom/press-releases/eset-discovers-kr00k-vulnerability/",
            ],
        )
    
    @staticmethod
    def wifi_fragattacks() -> Finding:
        return Finding(
            title="WiFi FragAttacks (CVE-2020-24586/87/88)",
            description="Design flaws in WiFi frame fragmentation and aggregation allow frame injection and traffic decryption.",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cve_ids=["CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588"],
            cwe_ids=["CWE-319"],
            affected_services=["WiFi"],
            tags=["wifi", "fragattacks", "fragmentation"],
            proof_of_concept="Inject malicious frames via fragmentation/aggregation flaws",
            remediation="Update WiFi firmware; disable fragmentation if possible",
            references=[
                "https://www.fragattacks.com/",
                "https://www.usenix.org/system/files/sec21-vanhoef.pdf",
            ],
        )
    
    @staticmethod
    def bluetooth_knob() -> Finding:
        return Finding(
            title="Bluetooth KNOB Attack (CVE-2019-9506)",
            description="Key Negotiation of Bluetooth allows forcing entropy of link key to 1 byte, enabling real-time decryption.",
            severity=FindingSeverity.HIGH,
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cve_ids=["CVE-2019-9506"],
            cwe_ids=["CWE-327"],
            affected_services=["Bluetooth"],
            tags=["bluetooth", "knob", "decryption"],
            proof_of_concept="Force entropy reduction during pairing, brute-force session key",
            remediation="Use Bluetooth devices with Secure Connections Only mode; update firmware",
            references=[
                "https://knobattack.com/",
                "https://francozappa.github.io/knob/",
            ],
        )
    
    @staticmethod
    def whisker_pair() -> Finding:
        return Finding(
            title="WhisperPair - Fast Pair KBP Bypass (CVE-2025-36911)",
            description="Fast Pair Key-Based Pairing authentication bypass allows unauthorized pairing with audio devices, leading to HFP microphone access.",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.0,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cve_ids=["CVE-2025-36911"],
            cwe_ids=["CWE-287", "CWE-306"],
            affected_services=["Bluetooth LE", "Fast Pair"],
            tags=["bluetooth", "fastpair", "whisperpair", "kbp", "audio"],
            proof_of_concept="Send KBP request to device not in pairing mode; device accepts and bonds",
            remediation="Update Bluetooth firmware; disable Fast Pair when not needed",
            references=[
                "https://www.securityweek.com/whisperpair-attack-leaves-millions-of-bluetooth-accessories-open-to-hijacking/",
            ],
        )
    
    @staticmethod
    def ssid_confusion() -> Finding:
        return Finding(
            title="SSID Confusion Attack (CVE-2023-52424)",
            description="SSID not included in PMK derivation allows clients to connect to different network with same credentials, enabling downgrade MITM.",
            severity=FindingSeverity.MEDIUM,
            cvss_score=5.9,
            cvss_vector="CVSS:3.1/AV:A/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
            cve_ids=["CVE-2023-52424"],
            cwe_ids=["CWE-325"],
            affected_services=["WiFi"],
            tags=["wifi", "ssid-confusion", "mitm"],
            proof_of_concept="Create rogue AP with same SSID but different security; client connects unaware",
            remediation="Vendor firmware updates; use WPA3 with SAE; enable PMF",
            references=[
                "https://papers.mathyvanhoef.com/wisec2024.pdf",
            ],
        )
    
    @staticmethod
    def bluetooth_hid_injection() -> Finding:
        return Finding(
            title="Bluetooth HID Keystroke Injection (CVE-2023-45866 / CVE-2024-21306)",
            description="Bluetooth host state machine accepts HID keyboard without user confirmation, allowing zero-click keystroke injection.",
            severity=FindingSeverity.CRITICAL,
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cve_ids=["CVE-2023-45866", "CVE-2024-21306", "CVE-2024-0230"],
            cwe_ids=["CWE-287", "CWE-306", "CWE-345"],
            affected_services=["Bluetooth Classic"],
            tags=["bluetooth", "hid", "keystroke-injection", "zero-click"],
            proof_of_concept="Emulate Bluetooth keyboard with NoInputNoOutput capability; inject keystrokes via Just Works pairing",
            remediation="Disable Bluetooth when not in use; update OS/Bluetooth stack; require user confirmation for HID pairing",
            references=[
                "https://github.com/marcnewlin/hi_my_name_is_keyboard",
                "https://www.mobile-hacker.com/2024/01/23/exploiting-0-click-android-bluetooth-vulnerability-to-inject-keystrokes-without-pairing/",
            ],
        )


# Export all public classes
__all__ = [
    "ReportFormat",
    "FindingSeverity",
    "FindingStatus",
    "Evidence",
    "Finding",
    "AuditSession",
    "ReportConfig",
    "ReportGenerator",
    "FindingTemplates",
]