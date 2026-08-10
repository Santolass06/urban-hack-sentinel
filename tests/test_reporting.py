"""Reporting pipeline tests.

Regression guard for the `urban-hs report` command, which previously called
a hallucinated API (`ReportGenerator(session_id=...).generate_summary_report`)
that does not exist. The real API is `ReportGenerator(config).generate(session, format)`.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from urban_hs.modules.reporting.generator import (
    AuditSession,
    ReportConfig,
    ReportFormat,
    ReportGenerator,
)


@pytest.mark.parametrize("fmt", [ReportFormat.MARKDOWN, ReportFormat.JSON])
async def test_report_generation_writes_file(tmp_path: Path, fmt: ReportFormat) -> None:
    generator = ReportGenerator(ReportConfig(output_dir=str(tmp_path), sign_report=False))
    session = AuditSession(id="audittest", name="Session audittest")

    generated = Path(await generator.generate(session, format=fmt))

    assert generated.exists()
    assert generated.stat().st_size > 0
