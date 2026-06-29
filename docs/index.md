# Urban Hack Sentinel v3 — Documentação

## Quick Links
- [README](../README.md) — Instalação, Docker, CLI, API, TUI, troubleshooting
- [Plano de execução](PLAN.md) — Estado actual, fases e critérios de aceitação
- [API Reference](API.md) — REST + WebSocket
- [Docker multi-arch](docker/MULTIARCH.md) — Build local `linux/amd64`, `linux/arm64`

## Módulos
- `urban_hs.modules.wifi` — Scanning, PMKID, handshake, WPS, deauth
- `urban_hs.modules.ble` — Fast Pair, WhisperPair (CVE-2025-36911)
- `urban_hs.modules.network` — Nmap, host discovery, service enum
- `urban_hs.modules.metasploit` — MSF RPC
- `urban_hs.modules.hid` — DuckyScript, HID injection
- `urban_hs.modules.mqtt` — Broker discovery + brute force
- `urban_hs.modules.camera` — mDNS/UPnP/ONVIF discovery
- `urban_hs.hal` — Hardware Abstraction Layer (WiFi `iw`/`scapy`, BLE `bleak`, detecção de plataforma)

## UI
- `urban_hs.cli` — CLI Typer (`urban-hs`)
- `urban_hs.ui.tui` — Dashboard Textual (`urban-hs-tui`)
- `urban_hs.ui.api` — FastAPI + WebSocket (`urban-hs-server`)
- `urban_hs.ui.web` — Frontend estático (HTMX + Alpine.js)

## Testes
```bash
pytest tests/ -v
```

## Smoke tests
- `docs/SMOKE_TUI.md`
- `tests/test_api_smoke.py`
- `tests/test_hal.py`
