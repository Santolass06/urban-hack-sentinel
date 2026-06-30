"""
Urban Hack Sentinel v3 — CLI entry point (Typer).

Commands
--------
* ``urban-hs info``    — print platform + capability summary.
* ``urban-hs run``     — bootstrap core services and keep running.
* ``urban-hs modules`` — list registered module plugins.
"""

from __future__ import annotations

import asyncio
import platform
import shutil
import signal
import sys
from typing import Optional

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


if __name__ == "__main__":
    app()
