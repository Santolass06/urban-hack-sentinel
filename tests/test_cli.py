"""
Smoke tests for the Urban Hack Sentinel CLI.

These tests validate that the Typer CLI boots and that the main commands
return expected exit codes / output without crashing.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


CMD = [sys.executable, "-m", "urban_hs.cli.main"]


def run_cli(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        CMD + args,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_cli_help() -> None:
    result = run_cli(["--help"])
    assert result.returncode == 0
    assert "Urban Hack Sentinel" in result.stdout or "Usage:" in result.stdout


def test_cli_info() -> None:
    result = run_cli(["info"])
    assert result.returncode == 0
    assert "Urban Hack Sentinel" in result.stdout
    assert "arch" in result.stdout


def test_cli_info_verbose() -> None:
    result = run_cli(["info", "--verbose"])
    assert result.returncode == 0
    assert "Capabilities" in result.stdout


def test_cli_modules() -> None:
    result = run_cli(["modules"])
    assert result.returncode == 0
    assert "Module Registry" in result.stdout


def test_cli_subprocess() -> None:
    result = run_cli(["info"])
    assert result.returncode == 0
    assert result.stdout.strip()
