# Urban Hack Sentinel v3 — Documentação

## Quick Links
- [README](../README.md) — Instalação, Docker, CLI, API, TUI, troubleshooting
- [Plano x86 + UI](PLAN_X86_UI.md) — Estratégia de portabilidade x86 e UI interativa
- [Plano de execução](PLAN_IMPLEMENTATION_2026-06-29.md) — Fases faseadas com critérios de aceitação

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

## Análise de integração
- `INTEGRATION_ANALYSIS.md` — WPair + Stryker → Urban Hack Sentinel
