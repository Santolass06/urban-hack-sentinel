# Urban Hack Sentinel v3

> Automated Wi-Fi/Bluetooth/IoT auditing platform for Raspberry Pi and x86/64.
> Modular Python 3.11+ framework with Wi-Fi scanning, WPA/WPA3 attacks, WPS, BLE, GPS wardriving, Metasploit integration, web/TUI/CLI dashboards, and a Hardware Abstraction Layer (HAL).

---

## 📚 Index

- [About](#about)
- [Installation](#installation)
- [Docker](#docker)
- [Usage](#usage)
- [Hardware](#hardware)
- [Architecture](#architecture)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Documentation](#documentation)
- [Project Status](#project-status)

---

## About

**Urban Hack Sentinel v3** turns a Raspberry Pi (or x86/64 machine) into a continuous-operation wireless/Bluetooth/IoT/network auditing platform.

### Capabilities

| Capability | Description |
|------------|-------------|
| **Wi-Fi Scanner** | Passive/active scan 2.4/5/6 GHz via `iw` JSON + `airodump-ng` fallback |
| **PMKID Attack** | Client-less PMKID capture (WPA2/WPA3) via `hcxdumptool` + `hcxpcapngtool` |
| **Handshake Capture** | Deauth + 4-way handshake via `aireplay-ng` + `airodump-ng` |
| **WPS Pixie Dust** | Offline PIN attack via `reaver --pixie-dust` |
| **WPS PIN Dictionary** | Common PIN database per OUI |
| **Deauth Attack** | Targeted/broadcast deauth via `aireplay-ng` |
| **MAC Randomization** | OUI profiles (Apple, Samsung, Intel, Realtek, Atheros) |
| **Handshake Manager** | Deduplication, Hashcat integration, WiGLE/Kismet export |
| **BLE/Fast Pair** | Fast Pair scanner, WhisperPair (CVE-2025-36911) vuln test, exploit chain |
| **Network Scanner** | Nmap wrapper, OS fingerprint, service enum |
| **Metasploit RPC** | Module execution, session management, exploit execution |
| **Camera Discovery** | mDNS/UPnP/ONVIF/RTSP/HTTP, default creds, vuln scanning |
| **HID/USB Gadget** | DuckyScript, HID injection, USB gadget profiles |
| **MQTT Attack Suite** | Broker discovery, topic enum, cred brute force |
| **ESP32 Fingerprinting** | CVE-2025-27840 passive detection |
| **SSID Confusion** | CVE-2023-52424 detection |
| **Bluetooth HID** | CVE-2023-45866, CVE-2024-21306 injection |

---

## Installation

### Prerequisites

- Python 3.11+
- Linux (kernel 6.x recommended)
- Wi-Fi adapter with monitor mode (ex: Alfa AWUS036ACH)
- Bluetooth BLE 4.2+ (built-in on Pi 5 or USB dongle)

### Local installation (Pi / x86)

```bash
git clone https://github.com/<owner>/urban-hack-sentinel
cd urban-hack-sentinel

python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

sudo apt update && sudo apt install -y \
    aircrack-ng hcxtools reaver bully macchanger iw jq \
    bluez bluez-tools gpsd gpsd-clients \
    nmap nuclei metasploit-framework hashcat \
    libgpgme-dev libbluetooth-dev libpcap-dev dbus libdbus-1-dev

sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool)
sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which nmap nuclei msfconsole)

cp config/config.env.example /etc/urban-hs/config.env
sudo vim /etc/urban-hs/config.env
```

---

## Docker

Multi-architecture builds supported (`linux/amd64`, `linux/arm64`).

```bash
# Build for current host
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .

# Build for specific arch
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.amd64 .

# Multi-arch build + push (requires buildx + registry)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<user>/urban-hack-sentinel:latest \
  --push

# Run ARM64
docker run --rm --network=host urban-hack-sentinel:latest urban-hs info

# Run x86_64
docker run --rm --platform linux/amd64 --network=host urban-hack-sentinel:latest urban-hs info
```

> **Note:** `--network=host` exposes ports directly and avoids bind conflicts on `0.0.0.0:8000`.

See [docker/MULTIARCH.md](docker/MULTIARCH.md) for local cross-compilation and QEMU setup.

---

## Usage

### CLI (`urban-hs`)

```bash
urban-hs info
urban-hs modules
urban-hs run
```

### Textual TUI (`urban-hs-tui`)

```bash
urban-hs-tui
```

Full-screen dashboard with tabs for Wi-Fi, BLE, Network, and an integrated terminal.

### FastAPI + Web dashboard (`urban-hs-server`)

```bash
urban-hs-server --host 0.0.0.0 --port 8000
```

REST API + WebSocket at `http://localhost:8000/`. Static frontend (HTMX + Alpine.js) served at `/`.

### Authentication

All API endpoints (except `/healthz` and `/auth/token`) require a Bearer token:

```bash
# Get a token
TOKEN=$(curl -s -X POST http://localhost:8000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "changeme"}' | jq -r '.access_token')

# Use the token
curl -H "Authorization: Bearer $TOKEN" http://localhost:8000/api/v1/info
```

### Exploit Runner — Autonomous Execution

The Exploit Runner (`modules/exploit/runner.py`) can autonomously:
1. Search ExploitDB for matching exploits
2. Download and execute them against target services
3. Collect proof-of-concept output

```python
from urban_hs.modules.exploit.runner import ExploitRunner

runner = ExploitRunner()
proof = await runner.run_exploit(
    exploit_id="42315",
    target_ip="192.168.1.100",
    target_port=8080,
    target_service="http",
)
print(proof.output)
```

### Key Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/healthz` | Health check |
| `GET` | `/api/v1/info` | System info |
| `GET` | `/api/v1/modules` | Module inventory |
| `POST` | `/api/v1/modules/{name}/execute` | Execute a module |
| `GET` | `/api/v1/wifi/interfaces` | Wi-Fi interfaces |
| `POST` | `/api/v1/wifi/scan` | Queue Wi-Fi scan |
| `GET` | `/api/v1/wifi/jobs/{job_id}` | Job status |
| `GET` | `/api/v1/ble/status` | BLE status |
| `POST` | `/api/v1/ble/scan` | Queue BLE scan |
| `POST` | `/api/v1/network/scan` | Queue network scan (nmap) |
| `GET` | `/api/v1/network/jobs/{job_id}` | Job status |
| `WS` | `/api/v1/events` | Real-time event stream |

---

## Hardware

| Component | Support | Notes |
|-----------|---------|-------|
| Raspberry Pi 5 (ARM64) | ✅ | Wi-Fi via Alfa AWUS036ACH (`wlan1`); integrated Bluetooth for basic BLE |
| x86/64 (Intel/AMD) | ✅ | Wi-Fi via `iw` (native chipsets) or scapy fallback |
| Alfa AWUS036ACH (MT7612U) | ✅ | Monitor mode + injection, `iw` backend |
| Intel AX210 | ✅ | Monitor patch required for monitor mode |
| CSR BLE 4.0/5.0 adapter | ✅ | Via bleak backend |
| u-blox GPS | 🔄 | gpsd + KML/CSV export |

> **Restriction:** Only the Alfa AWUS036ACH has been fully tested. Other chipsets work via scapy fallback but monitor mode is not guaranteed.

---

## Architecture

```
urban_hs/
├── core/                    # Shared infrastructure
│   ├── event_bus.py         # Async pub/sub
│   ├── config.py            # Pydantic v2 + StorageConfig
│   ├── storage.py           # SQLite WAL + Redis cache (optional)
│   └── plugins.py           # Plugin API
│
├── hal/                     # Hardware Abstraction Layer
│   ├── wifi/                # Wi-Fi backend (iw / scapy)
│   ├── ble/                 # BLE backend (bleak / BlueZ D-Bus)
│   ├── types.py             # Shared types (BLEDevice, etc.)
│   └── platform.py          # Platform detection (ARM64/x86)
│
├── modules/
│   ├── wifi/
│   │   ├── attacks/         # Handshake, PMKID, WPS, Deauth, Kr00k
│   │   │   ├── base.py      # BaseAttack, AttackResult, AttackStatus
│   │   │   ├── wpa.py       # HandshakeAttack, PMKIDAttack
│   │   │   ├── wps.py       # WPSPixieAttack, WPSPinAttack
│   │   │   └── deauth.py    # DeauthAttack, Kr00kAttack
│   │   ├── scanner.py       # AirodumpScanBackend, WiFiScanner
│   │   └── managers.py      # HandshakeManager, MACRandomizer
│   ├── ble/                 # Fast Pair + WhisperPair
│   ├── network/             # Nmap + Nuclei + Camera + Router
│   │   ├── types.py         # ScanType, Severity, PortInfo, HostInfo, Vulnerability
│   │   ├── scanner.py       # NmapScanner
│   │   ├── nuclei.py        # NucleiRunner
│   │   ├── searchsploit.py  # SearchSploitIntegration
│   │   ├── router.py        # RouterScanner
│   │   └── camera.py        # CameraDiscovery
│   ├── metasploit/          # MSF RPC
│   ├── credential/          # Credential handling + validation
│   ├── exploit/             # Exploit Runner (autonomous execution)
│   ├── reporting/           # Report generation (PDF, JSON, HTML)
│   └── plugins/             # Example/reference plugins
│
├── ui/
│   ├── api/
│   │   ├── auth.py          # Bearer token auth middleware
│   │   ├── main.py          # FastAPI app + CORS + rate limiting
│   │   └── routers/         # WiFi, BLE, Network, Attacks, System
│   ├── tui/                 # Textual TUI
│   └── web/                 # Static frontend (HTMX + Alpine.js)
│
├── cli/
│   └── main.py              # Typer CLI
│
├── chroot/                  # Chroot/jail helpers
└── tests/                   # pytest (99 tests)
```

---

## Testing

### Quick run

```bash
# All tests (excluding hardware-dependent)
pytest tests/ -v --ignore=tests/test_ble_module.py --ignore=tests/test_e2e.py

# Unit tests only
pytest tests/ -v -m unit

# Specific test files
pytest tests/test_attacks_base.py -v        # Attack types and base classes
pytest tests/test_attacks_submodules.py -v  # WPA/WPS/Deauth with mocks
pytest tests/test_network_module.py -v      # Network types and scanner
pytest tests/test_api_integration.py -v     # API with auth
pytest tests/test_hal.py -v                 # HAL tests (mocked)
```

### Code coverage

```bash
pytest --cov=src/urban_hs --cov-report=term-missing \
  --ignore=tests/test_ble_module.py --ignore=tests/test_e2e.py
```

Current coverage: **19%** (99 tests). Key covered areas:
- `network/types.py`: 100%
- `wifi/attacks/base.py`: 90%
- `ui/api/main.py`: 98%
- `core/config.py`: 76%

### Writing custom tests

- Place test files under `tests/` using the `test_*.py` naming convention.
- Use `@pytest.mark.unit` for pure logic and `@pytest.mark.integration` for tests that require hardware.
- Fixtures and helpers are shared via `tests/conftest.py`.
- Hardware-dependent tests should mock the HAL layer (`urban_hs.hal.*`) to keep CI green.
- For async tests, prefer `pytest-asyncio` with `@pytest.mark.anyio` or `async def` test functions.

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ModuleNotFoundError: No module named 'dbus'` in container | Ensure `libdbus-1-dev` is installed in the builder and `libdbus-1-3` + `dbus` in the runtime image. |
| Permission denied on `/var/log/urban-hs` | `sudo chown -R 1000:1000 /var/log/urban-hs /var/lib/urban-hs` |
| Port 8000 already in use | Use `--network=host` or change port with `--port 8001`. |
| BLE scan returns no devices | Check `bluetoothctl` and `bluetooth` group membership; some distros require `sudo`. |
| Monitor mode not available | Verify adapter chipset compatibility; use `iw list` to check for monitor mode support. |

---

## Documentation

- [Project index](docs/index.md) — Central documentation hub
- [Execution plan](docs/PLAN.md) — Current state, phases, and acceptance criteria
- [Phase 10 details](docs/PLAN_PHASE10.md) — Attack-selection UI tasks and mockups
- [API reference](docs/API.md) — REST + WebSocket contracts
- [TUI smoke test](docs/SMOKE_TUI.md) — Manual checklist for TUI on Pi
- [Docker multi-arch](docker/MULTIARCH.md) — Local `linux/amd64` / `linux/arm64` builds
- [Archive](docs/archive/) — Legacy/discontinued documents

---

## Project Status

- Phases **0–10** completed on branch `andreas/catarinus`
- Stack: HAL + API + TUI + Web UI + Tests + CI
- Next focus: real hardware validation (Alfa AWUS036ACH, Pi 5) and custom module expansion
