# Urban Hack Sentinel v3

> **Auditoria Wi-Fi/Bluetooth/IoT automatizada para Raspberry Pi e x86/64**
> Framework modular em Python 3.11+ com scanning WiFi, ataques WPA/WPA3, WPS, BLE, wardriving GPS, Metasploit integration, dashboard web/TUI/CLI, e camada de abstracção de hardware (HAL).

---

## 📚 Índice

- [O que faz](#-o-que-faz-esta-aplicação)
- [Instalação](#instalação)
- [Docker](#docker)
- [CLI, TUI e API](#cli-tui-e-api)
- [Hardware suportado](#hardware-suportado)
- [Arquitectura](#arquitectura)

---

## 🎯 O que faz esta aplicação

**Urban Hack Sentinel v3** transforma um Raspberry Pi (ou máquina x86/64) numa plataforma completa de auditoria wireless/Bluetooth/IoT/Network que opera continuamente:

### Core Capabilities
|| Capability | Descrição ||
|------------|-------------|
| **WiFi Scanner** | Passive/active scan 2.4/5/6 GHz via `iw` JSON + `airodump-ng` fallback |
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

## Instalação

### Pré-requisitos
- Python 3.11+
- Linux (kernel 6.x recomendado)
- Adaptador WiFi com modo monitor (ex: Alfa AWUS036ACH)
- Bluetooth BLE 4.2+ (built-in no Pi 5 ou dongle USB)

### Instalação local (Pi / x86)
```bash
git clone https://github.com/andresantos/urban-hack-sentinel
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

Suporta build multi-arquitectura (`linux/amd64,linux/arm64`).

```bash
# Build multi-arch
docker buildx build --platform linux/amd64,linux/arm64 \
  -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .

# Run ARM64
docker run --rm --network=host \
  urban-hack-sentinel:latest urban-hs info

# Run x86_64
docker run --rm --platform linux/amd64 --network=host \
  urban-hack-sentinel:latest urban-hs info
```

> Nota: A flag `--network=host` é usada para expor portas directamente e evitar conflitos de bind em `0.0.0.0:8000`.

---

## CLI, TUI e API

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
Dashboard full-screen com abas para WiFi, BLE, Network e terminal integrado.

### FastAPI + Web dashboard (`urban-hs-server`)
```bash
urban-hs-server --host 0.0.0.0 --port 8000
```
REST API + WebSocket em `http://localhost:8000/`. O frontend estático (HTMX + Alpine.js) é servido em `/`.

### Endpoints principais
| Método | Path | Descrição |
|--------|------|-----------|
| GET | `/healthz` | Health check |
| GET | `/api/v1/info` | Info do sistema |
| GET | `/api/v1/wifi/interfaces` | Interfaces WiFi |
| POST | `/api/v1/wifi/scan` | Iniciar scan WiFi |
| GET | `/api/v1/wifi/jobs/{job_id}` | Estado do job |
| GET | `/api/v1/ble/status` | Status BLE |
| GET | `/api/v1/ble/scan` | Scan BLE |
| POST | `/api/v1/network/scan` | Scan de network (nmap) |
| GET | `/api/v1/network/jobs/{job_id}` | Estado do job |

---

## Hardware suportado

| Componente | Suporte | Notas |
|------------|---------|-------|
| Raspberry Pi 5 (ARM64) | ✅ | WiFi via Alfa AWUS036ACH (wlan1); Bluetooth integrado para BLE básico |
| x86/64 (Intel/AMD) | ✅ | WiFi via `iw` (chipsets nativos) ou scapy fallback |
| Alfa AWUS036ACH (MT7612U) | ✅ | Monitor mode + injection, `iw` backend |
| Intel AX210 | ✅ | Monitor patch necessário para modo monitor |
| Adaptador CSR BLE 4.0/5.0 | ✅ | Via bleak backend |
| GPS u-blox | 🔄 | gpsd + export KML/CSV |

> Restrição: Apenas o adaptador Alfa AWUS036ACH foi testado até ao momento. Outros chipsets funcionam via scapy fallback mas sem garantia de modo monitor.

---

## Arquitectura

```
urban_hs/
├── core/                    # Infra-estrutura partilhada
│   ├── event_bus.py         # Async pub/sub
│   ├── config.py            # Pydantic v2
│   ├── storage.py           # SQLite WAL + JSONL
│   └── plugins.py           # Plugin API
│
├── hal/                     # Hardware Abstraction Layer
│   ├── wifi/                # WiFi backend (iw / scapy)
│   ├── ble/                 # BLE backend (bleak)
│   └── platform.py          # Detecção de plataforma (ARM64/x86)
│
├── modules/
│   ├── wifi/                # Scanner + Ataques WiFi
│   ├── ble/                 # Fast Pair + WhisperPair
│   ├── network/             # Nmap + Nuclei
│   ├── metasploit/          # MSF RPC
│   ├── hid/                 # DuckyScript + injector
│   ├── mqtt/                # MQTT attack suite
│   ├── camera/              # Descoberta de câmeras
│   └── ...
│
├── ui/
│   ├── api/                 # FastAPI + WebSocket
│   ├── tui/                 # Textual TUI
│   └── web/                 # Frontend estático
│
├── cli/
│   └── main.py              # Typer CLI
│
└── tests/                   # pytest
```

---

## 🧪 Testing

```bash
# Unit tests
pytest tests/ -v -m unit

# Testes de HAL (mock)
pytest tests/test_hal.py -v

# Testes de integração (requer hardware + .venv)
pytest tests/ -v -m integration --hardware
```

---

## 🛠 Troubleshooting

- **`ModuleNotFoundError: No module named 'dbus' no container**: Certificar que o Dockerfile instala `libdbus-1-dev` no builder e `libdbus-1-3` + `dbus` no runtime.
- **Permission denied em `/var/log/urban-hs`**: `sudo chown -R 1000:1000 /var/log/urban-hs /var/lib/urban-hs`
- **Port 8000 already in use**: Usar `--network=host` ou mudar porta com `--port 8001`.
- **BLE scan sem devices**: Verificar `bluetoothctl` e grupo `bluetooth`; em algumas distros requer `sudo`.

---

## 📄 Documentação adicional

- `docs/PLAN_X86_UI.md` — Plano de portabilidade x86 + UI interativa
- `docs/PLAN_IMPLEMENTATION_2026-06-29.md` — Plano de execução faseado
- `docs/index.md` — Índice de documentação
- `INTEGRATION_ANALYSIS.md` — Análise de integração WPair + Stryker

---

**Próximo passo**: Consumir `docs/PLAN_IMPLEMENTATION_2026-06-29.md` para fechar as fases 0-8 restantes.
