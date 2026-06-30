# Urban Hack Sentinel v3

> Auditoria Wi-Fi/Bluetooth/IoT automatizada para Raspberry Pi e x86/64.
> Framework modular em Python 3.11+ com scanning Wi-Fi, ataques WPA/WPA3, WPS, BLE, wardriving GPS, integração Metasploit, dashboard web/TUI/CLI e camada de abstracção de hardware (HAL).

---

## 📚 Índice

- [Sobre](#sobre)
- [Instalação](#instalação)
- [Docker](#docker)
- [Utilização](#utilização)
- [Hardware](#hardware)
- [Arquitectura](#arquitectura)
- [Testes](#testes)
- [Resolução de Problemas](#resolução-de-problemas)
- [Documentação](#documentação)
- [Estado do Projecto](#estado-do-projecto)

---

## Sobre

O **Urban Hack Sentinel v3** transforma um Raspberry Pi (ou máquina x86/64) numa plataforma de auditoria wireless/Bluetooth/IoT/network que opera continuamente.

### Capacidades

| Capacidade | Descrição |
|------------|-------------|
| **Wi-Fi Scanner** | Scan passivo/activo 2.4/5/6 GHz via `iw` JSON + fallback `airodump-ng` |
| **PMKID Attack** | Captura PMKID sem cliente (WPA2/WPA3) via `hcxdumptool` + `hcxpcapngtool` |
| **Handshake Capture** | Deauth + 4-way handshake via `aireplay-ng` + `airodump-ng` |
| **WPS Pixie Dust** | Ataque PIN offline via `reaver --pixie-dust` |
| **WPS PIN Dictionary** | Base de dados de PINs comuns por OUI |
| **Deauth Attack** | Deauth direcionado/broadcast via `aireplay-ng` |
| **MAC Randomization** | Perfis OUI (Apple, Samsung, Intel, Realtek, Atheros) |
| **Handshake Manager** | Deduplicação, integração Hashcat, exportação WiGLE/Kismet |
| **BLE/Fast Pair** | Scanner Fast Pair, teste de vulnerabilidade WhisperPair (CVE-2025-36911), cadeia de exploração |
| **Network Scanner** | Wrapper Nmap, fingerprint de SO, enumeração de serviços |
| **Metasploit RPC** | Execução de módulos, gestão de sessões, execução de exploits |
| **Camera Discovery** | mDNS/UPnP/ONVIF/RTSP/HTTP, credenciais por defeito, scanning de vulnerabilidades |
| **HID/USB Gadget** | DuckyScript, injecção HID, perfis de gadget USB |
| **MQTT Attack Suite** | Descoberta de brokers, enumeração de tópicos, força bruta de credenciais |
| **ESP32 Fingerprinting** | Detecção passiva CVE-2025-27840 |
| **SSID Confusion** | Detecção CVE-2023-52424 |
| **Bluetooth HID** | Injecção CVE-2023-45866, CVE-2024-21306 |

---

## Instalação

### Pré-requisitos

- Python 3.11+
- Linux (kernel 6.x recomendado)
- Adaptador Wi-Fi com modo monitor (ex: Alfa AWUS036ACH)
- Bluetooth BLE 4.2+ (integrado no Pi 5 ou dongle USB)

### Instalação local (Pi / x86)

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

Suporte a build multi-arquitectura (`linux/amd64`, `linux/arm64`).

```bash
# Build para arquitectura actual
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.arm64 .

# Build para arquitectura específica
docker build -t urban-hack-sentinel:latest -f docker/Dockerfile.amd64 .

# Multi-arch build + push (requer buildx + registry)
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t ghcr.io/<user>/urban-hack-sentinel:latest \
  --push

# Executar ARM64
docker run --rm --network=host urban-hack-sentinel:latest urban-hs info

# Executar x86_64
docker run --rm --platform linux/amd64 --network=host urban-hack-sentinel:latest urban-hs info
```

> **Nota:** A flag `--network=host` expõe portas directamente e evita conflitos de bind em `0.0.0.0:8000`.

Consulte [docker/MULTIARCH.md](docker/MULTIARCH.md) para compilação local cruzada e configuração QEMU.

---

## Utilização

### CLI (`urban-hs`)

```bash
urban-hs info
urban-hs modules
urban-hs run
```

### TUI Textual (`urban-hs-tui`)

```bash
urban-hs-tui
```

Dashboard em ecrã inteiro com separadores para Wi-Fi, BLE, Network e terminal integrado.

### FastAPI + dashboard web (`urban-hs-server`)

```bash
urban-hs-server --host 0.0.0.0 --port 8000
```

API REST + WebSocket em `http://localhost:8000/`. Frontend estático (HTMX + Alpine.js) servido em `/`.

### Endpoints principais

| Método | Path | Descrição |
|--------|------|-----------|
| `GET` | `/healthz` | Health check |
| `GET` | `/api/v1/info` | Informação do sistema |
| `GET` | `/api/v1/modules` | Inventário de módulos |
| `POST` | `/api/v1/modules/{name}/execute` | Executar módulo |
| `GET` | `/api/v1/wifi/interfaces` | Interfaces Wi-Fi |
| `POST` | `/api/v1/wifi/scan` | Colocar scan Wi-Fi na fila |
| `GET` | `/api/v1/wifi/jobs/{job_id}` | Estado do job |
| `GET` | `/api/v1/ble/status` | Estado BLE |
| `POST` | `/api/v1/ble/scan` | Colocar scan BLE na fila |
| `POST` | `/api/v1/network/scan` | Colocar scan de rede na fila (nmap) |
| `GET` | `/api/v1/network/jobs/{job_id}` | Estado do job |
| `WS` | `/api/v1/events` | Stream de eventos em tempo real |

---

## Hardware

| Componente | Suporte | Notas |
|-----------|---------|-------|
| Raspberry Pi 5 (ARM64) | ✅ | Wi-Fi via Alfa AWUS036ACH (`wlan1`); Bluetooth integrado para BLE básico |
| x86/64 (Intel/AMD) | ✅ | Wi-Fi via `iw` (chipsets nativos) ou fallback scapy |
| Alfa AWUS036ACH (MT7612U) | ✅ | Modo monitor + injeção, backend `iw` |
| Intel AX210 | ✅ | Patch de monitor necessário para modo monitor |
| Adaptador CSR BLE 4.0/5.0 | ✅ | Via backend bleak |
| u-blox GPS | ✅ | gpsd + parser NMEA + exportação KML/CSV/netXML/JSONL + modo wardrive |

> **Restrição:** Apenas o adaptador Alfa AWUS036ACH foi totalmente testado. Outros chipsets funcionam via fallback scapy, mas o modo monitor não é garantido.

---

## Arquitectura

```
urban_hs/
├── core/                    # Infra-estrutura partilhada
│   ├── event_bus.py         # Pub/sub assíncrono
│   ├── config.py            # Pydantic v2
│   ├── storage.py           # SQLite WAL + JSONL
│   └── plugins.py           # API de plugins
│
├── hal/                     # Camada de Abstracção de Hardware
│   ├── wifi/                # Backend Wi-Fi (iw / scapy)
│   ├── ble/                 # Backend BLE (bleak)
│   └── platform.py          # Detecção de plataforma (ARM64/x86)
│
├── modules/
│   ├── wifi/                # Scanner + ataques Wi-Fi
│   ├── ble/                 # Fast Pair + WhisperPair
│   ├── network/             # Nmap + Nuclei
│   ├── metasploit/          # RPC MSF
│   ├── hid/                 # DuckyScript + injector
│   ├── mqtt/                # Suíte de ataques MQTT
│   ├── camera/              # Descoberta de câmaras
│   ├── credential/          # Manipulação de credenciais
│   ├── exploit/             # Cadeias de exploração
│   ├── reporting/           # Geração de relatórios (PDF, JSON, HTML)
│   └── plugins/             # Plugins de exemplo/referência
│
├── ui/
│   ├── api/                 # FastAPI + WebSocket
│   ├── tui/                 # TUI Textual
│   └── web/                 # Frontend estático (HTMX + Alpine.js)
│
├── cli/
│   └── main.py              # CLI Typer
│
├── chroot/                  # Helpers de chroot/jail
└── tests/                   # pytest
```

---

## Testes

### Execução rápida

```bash
# Todos os testes
pytest tests/ -v

# Apenas unitários
pytest tests/ -v -m unit

# Testes HAL (hardware mockado)
pytest tests/test_hal.py -v

# Smoke tests da API
pytest tests/test_api_smoke.py -q

# Smoke tests da CLI
pytest tests/test_cli.py -q
```

### Cobertura de código

```bash
pytest --cov=src/urban_hs --cov-report=term-missing
```

Os limiares de cobertura são aplicados em CI. A base actual inclui testes HAL, integração API, CLI, contrato de eventos e smoke tests TUI.

### Desenvolver testes custom

- Coloque ficheiros de teste em `tests/` usando a convenção `test_*.py`.
- Use `@pytest.mark.unit` para lógica pura e `@pytest.mark.integration` para testes que requerem hardware.
- Fixtures e helpers são partilhados via `tests/conftest.py`.
- Testes dependentes de hardware devem mascarar a camada HAL (`urban_hs.hal.*`) para manter o CI verde.
- Para testes assíncronos, use `pytest-asyncio` com `@pytest.mark.anyio` ou funções de teste `async def`.

---

## Resolução de Problemas

| Problema | Solução |
|----------|---------|
| `ModuleNotFoundError: No module named 'dbus'` no contentor | Certifique-se que `libdbus-1-dev` está instalado no builder e `libdbus-1-3` + `dbus` no runtime. |
| Permission denied em `/var/log/urban-hs` | `sudo chown -R 1000:1000 /var/log/urban-hs /var/lib/urban-hs` |
| Porta 8000 em uso | Use `--network=host` ou mude a porta com `--port 8001`. |
| Scan BLE sem dispositivos | Verifique `bluetoothctl` e o grupo `bluetooth`; em algumas distribuições requer `sudo`. |
| Modo monitor indisponível | Verifique a compatibilidade do chipset; use `iw list` para confirmar suporte a modo monitor. |

---

## Documentação

- [Índice do projecto](docs/index.md) — Hub central de documentação
- [Plano de execução](docs/PLAN.md) — Estado actual, fases e critérios de aceitação
- [Detalhes da fase 10](docs/PLAN_PHASE10.md) — Tasks e mockups da UI de selecção de ataques
- [Referência API](docs/API.md) — Contratos REST + WebSocket
- [Smoke test TUI](docs/SMOKE_TUI.md) — Checklist manual para TUI no Pi
- [Multi-arquitectura Docker](docker/MULTIARCH.md) — Builds locais `linux/amd64` / `linux/arm64`
- [Arquivo](docs/archive/) — Documentos legados descontinuados

---

## Estado do Projecto

- Fases **0–10** concluídas no branch `andreas/catarinus`
- Stack: HAL + API + TUI + Web UI + Testes + CI
- Próximo foco: validação em hardware real (Alfa AWUS036ACH, Pi 5) e expansão de módulos custom
