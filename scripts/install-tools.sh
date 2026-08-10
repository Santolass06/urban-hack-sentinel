#!/usr/bin/env bash
#
# Install the external CLI tools the attack/scan modules shell out to.
# Debian/Ubuntu. Run with sudo:  sudo ./scripts/install-tools.sh
#
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "Run as root:  sudo $0" >&2
    exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> apt packages (Wi-Fi / network / IoT tooling)"
apt-get update
apt-get install -y \
    iw wireless-tools \
    aircrack-ng reaver pixiewps \
    hcxtools hcxdumptool \
    nmap tshark \
    hostapd mdk4 \
    gpsd gpsd-clients \
    avahi-utils \
    bettercap \
    exploitdb

echo "==> nuclei (not in apt — try snap, then GitHub release)"
if ! command -v nuclei >/dev/null 2>&1; then
    if command -v snap >/dev/null 2>&1 && snap install nuclei 2>/dev/null; then
        echo "    nuclei installed via snap"
    else
        NUCLEI_VER="3.3.7"
        ARCH="$(dpkg --print-architecture)"  # amd64 / arm64
        URL="https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_${ARCH}.zip"
        TMP="$(mktemp -d)"
        if curl -fsSL "$URL" -o "$TMP/nuclei.zip" && unzip -o "$TMP/nuclei.zip" -d "$TMP" >/dev/null; then
            install -m 0755 "$TMP/nuclei" /usr/local/bin/nuclei
            echo "    nuclei ${NUCLEI_VER} installed to /usr/local/bin"
        else
            echo "    WARNING: could not fetch nuclei; install it manually" >&2
        fi
        rm -rf "$TMP"
    fi
fi

echo "==> searchsploit (exploitdb) — provided by the exploitdb package above"
command -v searchsploit >/dev/null 2>&1 && searchsploit -u >/dev/null 2>&1 || true

echo "==> python-uinput into the project venv (local HID injection)"
if [[ -x "$ROOT/.venv/bin/pip" ]]; then
    "$ROOT/.venv/bin/pip" install python-uinput >/dev/null && echo "    python-uinput installed"
    modprobe uinput 2>/dev/null || true
fi

echo ""
echo "==> Verification"
for t in iw airodump-ng reaver pixiewps hcxdumptool nmap nuclei searchsploit \
         bettercap gpsd hostapd mdk4 tshark msfconsole; do
    if command -v "$t" >/dev/null 2>&1; then
        printf "  [x] %s\n" "$t"
    else
        printf "  [ ] %s  (MISSING)\n" "$t"
    fi
done

echo ""
echo "Done. WiFi scanning/attacks still require running the app as root"
echo "(sudo ./scripts/run-tui.sh) so iw/monitor-mode/raw sockets work."
