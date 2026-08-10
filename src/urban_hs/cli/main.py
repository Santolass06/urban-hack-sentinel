"""
Urban Hack Sentinel v3 — CLI entry point (Typer).

Commands
--------
* ``urban-hs info``              — print platform + capability summary.
* ``urban-hs run``               — bootstrap core services and keep running.
* ``urban-hs modules``           — list registered module plugins.
* ``urban-hs verify --session``  — verify evidence bundle integrity.
* ``urban-hs seal --session``    — seal session artifacts (planned).
* ``urban-hs audit-trail``       — print custody timeline for a session.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import shutil
import signal
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from urban_hs import __version__

app = typer.Typer(
    name="urban-hs",
    add_completion=False,
    no_args_is_help=True,
    help="Unified wireless / Bluetooth / IoT / Network auditing framework.",
)
console = Console()


@app.command()
def info(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show raw capability list."),
) -> None:
    """Print architecture / hardware summary."""
    try:
        from urban_hs.core.config import Config

        cfg = Config()
    except Exception:
        cfg = None  # type: ignore[assignment]

    table = Table(title="Urban Hack Sentinel — System Info")
    table.add_column("Key", style="cyan", no_wrap=True)
    table.add_column("Value", style="green")

    table.add_row("arch", platform.machine())
    table.add_row("system", platform.system())
    table.add_row("release", platform.release())
    table.add_row("python", platform.python_version())
    table.add_row("version", __version__)

    console.print(table)

    if verbose:
        caps = _detect_capabilities()
        cap_table = Table(title="Detected Capabilities")
        cap_table.add_column("Capability")
        cap_table.add_column("Available", justify="center")
        for name, ok in caps.items():
            cap_table.add_row(name, "[green]yes[/green]" if ok else "[red]no[/red]")
        console.print(cap_table)


@app.command()
def run(
    config_file: str | None = typer.Option(None, "--config", "-c", help="Config YAML path."),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level."),
    wardrive: bool = typer.Option(False, "--wardrive", "-w", help="Enable dedicated wardrive mode (continuous scan + GPS logging, no active attacks)."),
) -> None:
    """Bootstrap core services and run until Ctrl-C."""

    async def _main() -> None:
        try:
            from urban_hs.core import init_core, shutdown_core
            from urban_hs.core.config import get_config
        except ImportError as exc:
            console.print(f"[red]Core not available:[/red] {exc}")
            sys.exit(1)

        loop = asyncio.get_running_loop()
        stop = loop.create_future()

        def _signal() -> None:
            if not stop.done():
                stop.set_result(None)

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _signal)
            except NotImplementedError:
                # Windows não suporta add_signal_handler
                signal.signal(sig, lambda *_: _signal())

        try:
            await init_core(config_file=config_file, log_level=log_level)
            cfg = get_config()
            if wardrive:
                cfg.wifi.enable_active_attacks = False
                cfg.wifi.passive_scan = True
                console.print("[bold cyan]Wardrive mode enabled: passive scanning + GPS logging only (active attacks disabled).[/bold cyan]")
            console.print("[green]Core initialised. Press Ctrl-C to stop.[/green]")
            await stop
            console.print("\n[yellow]Shutting down…[/yellow]")
        except Exception as exc:
            console.print(f"[red]Fatal error:[/red] {exc}")
            sys.exit(1)
        finally:
            await shutdown_core()

    asyncio.run(_main())


@app.command()
def tui() -> None:
    """Launch the terminal UI dashboard."""
    from urban_hs.ui.tui.app import run

    run()


@app.command(name="modules")
def list_modules() -> None:
    """List registered module plugins."""
    try:
        from urban_hs.modules import _MODULE_REGISTRY
    except ImportError as exc:
        console.print(f"[red]Modules package not available:[/red] {exc}")
        raise typer.Exit(1)

    table = Table(title="Module Registry")
    table.add_column("Module", style="cyan")
    table.add_column("Plugin Class", style="green")
    for name, cls in sorted(_MODULE_REGISTRY.items()):
        table.add_row(name, cls)
    console.print(table)


def _detect_capabilities() -> dict[str, bool]:
    """Best-effort hardware + tooling capability probe."""
    tools = [
        "bluetoothctl",
        "iw",
        "aircrack-ng",
        "hcxdumptool",
        "hcxpcapngtool",
        "reaver",
        "bully",
        "macchanger",
        "nmap",
        "nuclei",
        "msfconsole",
        "hashcat",
        "gpsd",
        "btmgmt",
        "hcitool",
        "hcidump",
    ]
    return {name: shutil.which(name) is not None for name in tools}


@app.command(name="verify")
def verify_session(
    session_id: str = typer.Argument(..., help="Session ID to verify."),
    index: str | None = typer.Option(None, "--index", help="Evidence index path."),
) -> None:
    """Verify evidence bundle integrity (GPG + hashes + chain)."""
    try:
        from urban_hs.core.forensics import EvidenceBundle
    except ImportError as exc:
        console.print(f"[red]Forensics module not available:[/red] {exc}")
        raise typer.Exit(1)

    bundle = EvidenceBundle(session_id=session_id)
    if index:
        bundle.index_path = lambda *args, **kwargs: index  # type: ignore[assignment]

    idx = bundle.index_path()
    if not os.path.exists(idx):
        console.print(f"[red]Index not found:[/red] {idx}")
        raise typer.Exit(1)

    try:
        data = json.loads(Path(idx).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to parse index:[/red] {exc}")
        raise typer.Exit(1)

    errors: list[str] = []
    for artifact in data.get("artifacts", []):
        path = artifact.get("path")
        expected_sha = artifact.get("sha256")
        expected_blake = artifact.get("blake2b")
        if not path or not os.path.exists(path):
            errors.append(f"missing artifact: {path}")
            continue
        actual_sha = EvidenceBundle._sha256(path)
        actual_blake = EvidenceBundle._blake2b(path)
        if expected_sha and actual_sha != expected_sha:
            errors.append(f"sha256 mismatch: {path}")
        if expected_blake and actual_blake != expected_blake:
            errors.append(f"blake2b mismatch: {path}")

    custody = data.get("custody", [])
    for i, entry in enumerate(custody):
        if not entry.get("path") or not entry.get("ts"):
            errors.append(f"custody entry {i} incomplete")

    if errors:
        console.print(f"[red]Verification failed ({len(errors)} issue(s)):[/red]")
        for err in errors:
            console.print(f"  - {err}")
        raise typer.Exit(2)

    console.print(f"[green]Session {session_id} verified OK.[/green]")
    console.print(f"Artifacts: {len(data.get('artifacts', []))}")
    console.print(f"Custody entries: {len(custody)}")


@app.command(name="seal")
def seal_session(
    session_id: str = typer.Argument(..., help="Session ID to seal."),
    target_dir: str | None = typer.Option(None, "--target-dir", help="Destination path for sealed storage."),
) -> None:
    """Move session artifacts to append-only / read-only sealed storage."""
    try:
        from urban_hs.core.forensics import EvidenceBundle
    except ImportError as exc:
        console.print(f"[red]Forensics module not available:[/red] {exc}")
        raise typer.Exit(1)

    bundle = EvidenceBundle(session_id=session_id)
    idx = bundle.index_path()
    if os.path.exists(idx):
        try:
            data = json.loads(Path(idx).read_text(encoding="utf-8"))
            bundle.records = data.get("artifacts", [])
            bundle.custody_entries = data.get("custody", [])
        except Exception:
            pass

    try:
        manifest_path = bundle.seal(target_dir=target_dir)
        console.print(f"[green]Session {session_id} sealed successfully.[/green]")
        console.print(f"Sealed manifest: [cyan]{manifest_path}[/cyan]")
    except Exception as exc:
        console.print(f"[red]Failed to seal session {session_id}:[/red] {exc}")
        raise typer.Exit(1)


@app.command(name="audit-trail")
def audit_trail(
    session_id: str = typer.Argument(..., help="Session ID to inspect."),
    index: str | None = typer.Option(None, "--index", help="Evidence index path."),
) -> None:
    """Print readable audit/custody timeline for a session."""
    try:
        from urban_hs.core.forensics import EvidenceBundle
    except ImportError as exc:
        console.print(f"[red]Forensics module not available:[/red] {exc}")
        raise typer.Exit(1)

    bundle = EvidenceBundle(session_id=session_id)
    if index:
        bundle.index_path = lambda *args, **kwargs: index  # type: ignore[assignment]

    idx = bundle.index_path()
    if not os.path.exists(idx):
        console.print(f"[red]Index not found:[/red] {idx}")
        raise typer.Exit(1)

    try:
        data = json.loads(Path(idx).read_text(encoding="utf-8"))
    except Exception as exc:
        console.print(f"[red]Failed to parse index:[/red] {exc}")
        raise typer.Exit(1)

    custody = data.get("custody", [])
    if not custody:
        console.print("[yellow]No custody entries found.[/yellow]")
        return

    table = Table(title=f"Audit trail: {session_id}")
    table.add_column("Time", style="cyan")
    table.add_column("Action")
    table.add_column("Path")
    for entry in custody:
        table.add_row(
            entry.get("ts", ""),
            entry.get("action", ""),
            entry.get("path", ""),
        )
    console.print(table)


@app.command(name="report")
def generate_report(
    session_id: str = typer.Option("default", "--session", help="Session ID."),
    format_type: str = typer.Option("markdown", "--format", "-f", help="Output format: markdown, html, json."),
    output: str | None = typer.Option(None, "--output", "-o", help="Output destination file path."),
) -> None:
    """Generate executive audit report for session (Issue #2.1)."""
    try:
        from urban_hs.modules.reporting.generator import (
            AuditSession,
            ReportFormat,
            ReportGenerator,
        )

        fmt = ReportFormat(format_type.lower())

        # Build the audit session, enriching it from the evidence custody
        # trail if one exists (same index the seal/audit-trail commands use).
        from datetime import UTC, datetime

        session = AuditSession(id=session_id, name=f"Session {session_id}")
        session.end_time = datetime.now(UTC)
        try:
            from urban_hs.core.forensics import EvidenceBundle

            idx = EvidenceBundle(session_id=session_id).index_path()
            if os.path.exists(idx):
                data = json.loads(Path(idx).read_text(encoding="utf-8"))
                custody = data.get("custody", [])
                session.metadata["custody_entries"] = custody
                session.metadata["custody_count"] = len(custody)
        except Exception:
            pass  # Report is still valid without the custody trail.

        generator = ReportGenerator()
        generated_path = Path(asyncio.run(generator.generate(session, format=fmt)))

        if output:
            out_path = Path(output)
            out_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(generated_path), str(out_path))
        else:
            out_path = generated_path
        console.print(f"[bold green]Audit report generated successfully:[/bold green] [cyan]{out_path}[/cyan]")
    except Exception as exc:
        console.print(f"[red]Report generation failed:[/red] {exc}")
        raise typer.Exit(1)


if __name__ == "__main__":
    app()
