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
from typing import List, Optional

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
    config_file: Optional[str] = typer.Option(None, "--config", "-c", help="Config YAML path."),
    log_level: str = typer.Option("INFO", "--log-level", help="Logging level."),
) -> None:
    """Bootstrap core services and run until Ctrl-C."""

    async def _main() -> None:
        try:
            from urban_hs.core import init_core, shutdown_core
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
            console.print("[green]Core initialised. Press Ctrl-C to stop.[/green]")
            await stop
            console.print("\n[yellow]Shutting down…[/yellow]")
        except Exception as exc:
            console.print(f"[red]Fatal error:[/red] {exc}")
            sys.exit(1)
        finally:
            await shutdown_core()

    asyncio.run(_main())


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
    index: Optional[str] = typer.Option(None, "--index", help="Evidence index path."),
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
) -> None:
    """Move session artifacts to append-only storage."""
    console.print(
        f"[yellow]Seal is not yet implemented for session {session_id}.[/yellow]"
    )
    console.print(
        "Expected behaviour: relocate artifacts under /var/lib/urban-hs/sealed/<session_id>/ and set immutable flags."
    )


@app.command(name="audit-trail")
def audit_trail(
    session_id: str = typer.Argument(..., help="Session ID to inspect."),
    index: Optional[str] = typer.Option(None, "--index", help="Evidence index path."),
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


if __name__ == "__main__":
    app()
