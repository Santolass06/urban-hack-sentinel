#!/usr/bin/env bash
#
# Launch the Urban Hack Sentinel TUI with the privileges that WiFi scanning
# and attacks require (iw scan / monitor mode / raw sockets all need root).
#
#   ./scripts/run-tui.sh
#
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="$ROOT/.venv/bin/urban-hs-tui"

if [[ ! -x "$BIN" ]]; then
    echo "venv not found. Create it first:" >&2
    echo "  python3 -m venv .venv && .venv/bin/pip install -e ." >&2
    exit 1
fi

if [[ $EUID -eq 0 ]]; then
    exec "$BIN" "$@"
fi

echo "WiFi scanning/attacks need root — re-launching under sudo…"
# Preserve the env vars the app reads (MSF creds, environment mode).
exec sudo --preserve-env=URBAN_HS_MSF_PASSWORD,URBAN_HS_MSF_HOST,URBAN_HS_MSF_PORT,URBAN_HS_MSF_USER,URBAN_HS_ENVIRONMENT_MODE \
    "$BIN" "$@"
