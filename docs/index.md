# Urban Hack Sentinel v3 Documentation

Welcome to the official documentation for **Urban Hack Sentinel v3** - a unified wireless/Bluetooth/IoT auditing framework for Raspberry Pi *and* x86/64.

## Quick Links

- [Getting Started](getting-started/installation.md) - Installation and quick start guide
- [Architecture](core/architecture.md) - System architecture overview
- [API Reference](reference/api.md) - Complete API documentation
- [Modules](modules/index.md) - All available modules
- [UI/UX](ui/index.md) - Web, TUI, and CLI interfaces
- [Development](development/contributing.md) - Contributing guidelines

## Feature Overview

| Module | Status | Description |
|--------|--------|-------------|
| **WiFi** | ✅ | Scanner, PMKID, Handshake, WPS, Deauth |
| **BLE** | ✅ | Fast Pair, WhisperPair (CVE-2025-36911) |
| **Network** | ✅ | Nmap, Nuclei, Camera Discovery |
| **Metasploit** | ✅ | RPC, Console, Exploitation |
| **HID/USB** | ✅ | DuckyScript, HID Injection, Gadget Profiles |
| **Camera** | ✅ | Discovery, Enumeration, Vuln Scanning |
| **Exploits** | ✅ | Custom exploits (Bluetooth HID, Kr00k, etc.) |
| **MQTT** | ✅ | Broker Discovery, Topic Enum, Cred Brute |
| **ESP32** | ✅ | CVE-2025-27840 HCI Commands |
| **SSID Confusion** | ✅ | CVE-2023-52424 Detection |

## Sprint Progress

| Sprint | Completion | Description |
|--------|------------|-------------|
| S0 Foundation | 100% | Core infrastructure, health, scheduler, plugins, CI/CD |
| S1 WiFi | 100% | Scanner, attacks, managers, geo, tests |
| S2 BLE | 100% | Fast Pair, WhisperPair, HFP Audio |
| S3 Network/Camera | 100% | Nmap, Nuclei, Camera Enum/Vuln |
| S4 Metasploit/Exploit | 100% | RPC, Exploits, Reporting |
|| S5 HID/Dashboard | 90% | HID complete, UI (TUI + Web + API) shipped |
|| S6 Polish | 80% | Concurrency, Memory, SQLite, Security, Docs |

## Quick Navigation

- [Installation Guide](getting-started/installation.md)
- [Hardware Requirements](getting-started/hardware.md)
- [Configuration](getting-started/configuration.md)
- [Architecture Overview](core/architecture.md)
- [API Reference](reference/api.md)
- [Modules](modules/index.md)
- [UI/UX](ui/index.md)
- [Development Guide](development/contributing.md)

## Support

- **Issues**: [GitHub Issues](https://github.com/Santolass06/urban-hack-sentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/Santolass06/urban-hack-sentinel/discussions)
- **Security**: [Security Policy](SECURITY.md)

---

*Urban Hack Sentinel v3 - Unified wireless/Bluetooth/IoT auditing for Raspberry Pi*