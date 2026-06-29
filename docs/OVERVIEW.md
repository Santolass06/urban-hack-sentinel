# Urban Hack Sentinel — Project Overview

A technically accurate, plain-language story of why this project exists, what it does, and who it is for.

---

## The name

**Urban** — the project focuses on technologies you find in cities: Wi-Fi networks, Bluetooth devices, smart cameras, IoT gadgets, MQTT brokers. It is not about obscure military-grade kits; it is about the `wlan0` you see at a café, the BLE beacon on a bus stop, the IP camera above a shop door.

**Hack** — not in the movie sense. Here it means: understand how something works by taking it apart, probing its assumptions, and documenting what breaks. The project attacks networks and protocols, but only to show that they break in predictable, reproducible ways.

**Sentinel** — the system is meant to run unattended. A Raspberry Pi in a backpack, powered by a power bank, scanning while you walk through the city. It watches. It records. It reports. The operator does not have to babysit every step.

---

## How it started

This project began with a question: *How easy is it to break the wireless networks people use every day?*

In 2024, while studying cybersecurity, I tested a hypothesis. I put a Raspberry Pi, an Alfa AWUS036ACH Wi-Fi adapter, a power bank, and a GPS receiver into a backpack. I walked through a main avenue in a medium-sized European city, scanning Wi-Fi networks and capturing WPA/WPA2 handshakes. The result was unsettling. Within a single afternoon I collected keys from networks that people assume to be private, using less than €150 in hardware and no specialised skill beyond what anyone can learn from public documentation.

That experiment became a series of questions:

- What happens when WPA3 meets a flawed implementation?
- Can a Bluetooth device be impersonated without the owner noticing?
- Are the "smart" cameras street-side still using default credentials?
- Which CVEs are still exploitable in 2026, and which are just noise?

Instead of running isolated `aircrack-ng` commands by hand, I started building a structured framework. The goal was not just to collect data, but to make the process reproducible, modular, and shareable. That framework became **Urban Hack Sentinel**.

---

## What it does

Urban Hack Sentinel is a modular auditing platform for wireless, Bluetooth, IoT, and network technologies commonly found in urban environments. It runs on a Raspberry Pi or any x86/64 Linux machine and exposes three interfaces:

- **CLI** (`urban-hs`) — for scripting and automation.
- **TUI** (`urban-hs-tui`) — a full-screen Textual dashboard for live operation in the field.
- **Web dashboard** (`urban-hs-server`) — a REST API + WebSocket + browser UI for remote monitoring or integration with other tools.

Under the hood, every capability is a plugin: Wi-Fi scanning, PMKID capture, WPS attacks, BLE Fast Pair / WhisperPair, Nmap scans, Metasploit RPC, camera discovery, HID injection, MQTT brute force, and more. New plugins can be added without touching the core framework.

The system is designed for **continuous operation**. It discovers hardware automatically (HAL — Hardware Abstraction Layer), selects the best backend (`iw`, `scapy`, `bleak`, `nmap`, etc.), and streams events through an internal event bus. The UI reacts in real time.

---

## The learning path

This is not a finished product. It is a **learning vehicle**.

I am a student. I learn by doing. Each module in the project corresponds to a technology I wanted to understand:

- I implemented the Wi-Fi module because I wanted to see how channels and client isolation behave.
- I added Bluetooth HID attacks after reading CVE-2023-45866 and CVE-2024-21306.
- I integrated Metasploit RPC because I wanted to move from standalone `msfconsole` invocations to structured session management.
- I added the HAL and multi-architecture Docker builds to learn how software targets different hardware without forking.

When I get stuck, I delegate implementation decisions to an AI assistant. I review the generated code, learn from it, and iterate. This document is part of that loop: explaining the project clearly forces me to understand it myself.

---

## Who it is for

The project is intentionally broad in audience.

**Beginners in cybersecurity** can use the existing UI as a safe, guided way to run scans and see results. The capability table in the README explains what each module does before they ever type a command.

**Experienced operators** can write custom plugins. The plugin API is documented, the event bus is typed, and the HAL abstracts hardware quirks so they can focus on the attack logic rather than platform detection.

**Students and researchers** can use the code as a reference. The modular structure shows how to organise a Python project with async event handling, plugin discovery, hardware abstraction, and multiple presentation layers from a single codebase.

**Curious non-technical readers** can read this overview and understand the threat model: that common consumer technologies have flaws, that those flaws are reproducible, and that awareness is the first step to choosing safer alternatives.

---

## Threat model and ethics

Urban Hack Sentinel attacks are performed **only on networks and devices you own or have explicit permission to audit**. This is not a grey-area tool. Operating it against infrastructure you do not own is illegal in most jurisdictions and against the project ethos.

The platform is designed to be **observable**. Every action goes through the event bus. Every plugin can be audited. Running with `dry_run=true` executes the plugin logic without touching hardware, which is the recommended mode for learning and demonstration.

---

## Current state

As of mid-2026, **phases 0–10** are complete on branch `andreas/catarinus`:

- Core event bus, configuration, storage, and plugin registry.
- HAL for Wi-Fi (`iw` + `scapy` fallback) and Bluetooth (`bleak`).
- Modules for Wi-Fi, BLE, network scanning, Metasploit, HID, MQTT, cameras, and credential handling.
- CLI, TUI, and web interfaces wired to the same backend.
- REST API with attack inventory and execution endpoints.
- WebSocket event stream standardised to `attack.started`, `attack.progress`, `attack.completed`, `attack.error`.
- Example plugins and a Ghostwriter-like reporting module.
- Multi-architecture Docker builds (`linux/amd64`, `linux/arm64`).
- Test suite covering HAL, API, CLI, event contracts, and TUI smoke tests.

What comes next depends on what I need to learn next: real hardware validation on the Alfa AWUS036ACH and Pi 5, deeper Metasploit integration, GPS-based wardriving maps, or publishing module templates for the community.

---

## Design philosophy

1. **One codebase, many interfaces.** The CLI, TUI, and web UI share the same backend. Adding a feature once makes it available everywhere.
2. **Hardware is a plugin.** The HAL means the same attack runs on a Pi with an Alfa adapter, an x86 laptop with an Intel AX210, or a cloud VM with virtual interfaces mocked for CI.
3. **Events over polling.** The UI does not ask "are you done yet?" every second. The backend pushes progress through the event bus, and the UI renders it.
4. **Extensibility by convention.** To add a new module, you create a class, register it, and emit standard events. You do not modify routers, UI code, or storage layers.
5. **Transparency over obscurity.** Everything that touches hardware is logged, structured, and capturable. There are no silent `os.system` calls that disappear into the ether.

---

## Acknowledgments

This project exists because a university forces students to learn by building, because open-source security researchers document CVEs and exploits publicly, and because AI-assisted development tools make it possible for a single student to iterate faster than would have been possible five years ago.

If you are reading this and you are also learning: build something. Break it. Document why it broke. That is the only path that actually sticks.
