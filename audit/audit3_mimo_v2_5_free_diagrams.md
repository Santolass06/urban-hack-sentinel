# Audit Diagrams — audit3_mimo_v2_5_free

## 1. High-Level Architecture / Data Flow

```mermaid
graph TB
    subgraph "User Interfaces"
        CLI["CLI<br/>(Typer)"]
        TUI["TUI<br/>(Textual)"]
        WEB["Web UI<br/>(HTMX + Alpine.js)"]
    end

    subgraph "API Layer"
        FASTAPI["FastAPI<br/>REST + WebSocket"]
        ROUTERS["API Routers<br/>system / wifi / ble /<br/>network / attacks / events"]
    end

    subgraph "Core Infrastructure"
        EBUS["Event Bus<br/>(asyncio.Queue pub/sub)"]
        CONFIG["Config<br/>(Pydantic Settings)"]
        STORAGE["Storage<br/>(aiosqlite WAL + Redis)"]
        PROC["Process Manager<br/>(asyncio.subprocess)"]
        HEALTH["Health + Metrics<br/>(Prometheus)"]
        PLUGINS["Plugin System<br/>(dynamic load)"]
        SCHED["Scheduler<br/>(cron/interval)"]
        LOG["Logger<br/>(structlog + JSONL)"]
        SECURITY["Security<br/>(seccomp, caps, chroot)"]
        CONC["Concurrency<br/>(resource pools)"]
        MEM["Memory Profiler<br/>(streaming parsers)"]
    end

    subgraph "Hardware Abstraction Layer"
        WIFI_HAL["WiFi HAL<br/>iw / scapy backend"]
        BLE_HAL["BLE HAL<br/>bleak backend"]
        PLAT["Platform Detect<br/>ARM64 / x86"]
    end

    subgraph "Attack Modules"
        WIFI_MOD["WiFi Module<br/>Scanner + Attacks"]
        BLE_MOD["BLE Module<br/>FastPair + WhisperPair"]
        NET_MOD["Network Module<br/>Nmap + Nuclei"]
        CAM_MOD["Camera Module<br/>mDNS + ONVIF + RTSP"]
        MSF_MOD["Metasploit Module<br/>RPC + Console"]
        HID_MOD["HID Module<br/>DuckyScript + Injector"]
        MQTT_MOD["MQTT Module<br/>Broker + Brute"]
        BT_HID["BT HID Module<br/>CVE-2023-45866"]
        EXP_MOD["Exploit Runner<br/>Generic pipeline"]
        CRED_MOD["Credential Manager<br/>Normalization + Export"]
        RPT_MOD["Reporting<br/>PDF/HTML/Markdown"]
        ESP32["ESP32 Fingerprinting<br/>CVE-2025-27840"]
        SSID["SSID Confusion<br/>CVE-2023-52424"]
    end

    subgraph "External Tools (subprocess)"
        AIRCRACK["aircrack-ng suite"]
        HCX["hcxdumptool / hcxpcapngtool"]
        REAVER["reaver / bully"]
        NMAP["nmap / nuclei"]
        HASHCAT["hashcat"]
        MSF["msfconsole / msfRPC"]
        BLUEZ["BlueZ / bluetoothctl"]
        GPSD["gpsd"]
    end

    subgraph "Chroot (optional)"
        ALPINE["Alpine Linux Chroot<br/>Isolated tool execution"]
    end

    CLI --> FASTAPI
    TUI --> FASTAPI
    WEB --> FASTAPI
    FASTAPI --> ROUTERS
    ROUTERS --> EBUS
    ROUTERS --> WIFI_MOD
    ROUTERS --> BLE_MOD
    ROUTERS --> NET_MOD

    EBUS --> PLUGINS
    PLUGINS --> WIFI_MOD
    PLUGINS --> BLE_MOD
    PLUGINS --> NET_MOD
    PLUGINS --> CAM_MOD
    PLUGINS --> MSF_MOD
    PLUGINS --> HID_MOD
    PLUGINS --> MQTT_MOD
    PLUGINS --> BT_HID
    PLUGINS --> EXP_MOD
    PLUGINS --> CRED_MOD
    PLUGINS --> RPT_MOD
    PLUGINS --> ESP32
    PLUGINS --> SSID

    WIFI_MOD --> WIFI_HAL
    BLE_MOD --> BLE_HAL
    WIFI_HAL --> AIRCRACK
    WIFI_HAL --> HCX
    WIFI_HAL --> REAVER
    NET_MOD --> NMAP
    MSF_MOD --> MSF
    EXP_MOD --> HASHCAT
    RPT_MOD --> PROC

    PROC --> ALPINE
    PLAT --> WIFI_HAL
    PLAT --> BLE_HAL

    STORAGE --> CONFIG
    HEALTH --> EBUS
    LOG --> EBUS
    CONC --> EBUS
    MEM --> PROC
    SECURITY --> PROC

    WIFI_HAL --> EBUS
    BLE_HAL --> EBUS
    NET_MOD --> EBUS
    MSF_MOD --> EBUS
```

## 2. Internal Module Dependency Graph

```mermaid
graph LR
    subgraph "Core"
        config["core.config"]
        event_bus["core.event_bus"]
        storage["core.storage"]
        process_mgr["core.process_mgr"]
        plugins["core.plugins"]
        health["core.health"]
        scheduler["core.scheduler"]
        logger["core.logger"]
        security["core.security"]
        concurrency["core.concurrency"]
        memory["core.memory"]
    end

    subgraph "HAL"
        hal_wifi["hal.wifi"]
        hal_ble["hal.ble"]
        hal_platform["hal.platform"]
    end

    subgraph "Modules"
        wifi_plugin["modules.wifi.plugin"]
        wifi_scanner["modules.wifi.scanner"]
        wifi_attacks["modules.wifi.attacks"]
        ble_plugin["modules.ble.plugin"]
        ble_fastpair["modules.ble.fastpair"]
        ble_exploit["modules.ble.exploit_chain"]
        net_mod["modules.network"]
        cam_mod["modules.camera"]
        msf_mod["modules.metasploit"]
        hid_mod["modules.hid"]
        mqtt_mod["modules.mqtt"]
        exploit_mod["modules.exploit"]
        cred_mod["modules.credential"]
        rpt_mod["modules.reporting"]
        bt_hid["modules.bt_hid"]
        esp32_mod["modules.esp32"]
        ssid_mod["modules.ssid_confusion"]
    end

    subgraph "UI"
        api_main["ui.api.main"]
        tui_app["ui.tui.app"]
        cli_main["cli.main"]
    end

    config --> event_bus
    storage --> event_bus
    storage --> config
    plugins --> event_bus
    plugins --> config
    health --> event_bus
    health --> storage
    scheduler --> event_bus
    logger --> config
    security --> process_mgr
    concurrency --> event_bus
    memory --> process_mgr

    hal_wifi --> config
    hal_wifi --> event_bus
    hal_ble --> config
    hal_platform --> config

    wifi_plugin --> wifi_scanner
    wifi_plugin --> wifi_attacks
    wifi_scanner --> hal_wifi
    wifi_scanner --> event_bus
    wifi_attacks --> process_mgr
    wifi_attacks --> event_bus

    ble_plugin --> ble_fastpair
    ble_plugin --> ble_exploit
    ble_fastpair --> hal_ble
    ble_fastpair --> event_bus
    ble_exploit --> hal_ble
    ble_exploit --> event_bus

    net_mod --> process_mgr
    net_mod --> event_bus
    cam_mod --> process_mgr
    cam_mod --> event_bus
    msf_mod --> process_mgr
    msf_mod --> event_bus
    hid_mod --> process_mgr
    mqtt_mod --> event_bus
    exploit_mod --> process_mgr
    exploit_mod --> event_bus
    cred_mod --> storage
    rpt_mod --> storage
    rpt_mod --> process_mgr
    bt_hid --> hal_ble
    esp32_mod --> hal_ble
    ssid_mod --> hal_wifi

    api_main --> event_bus
    api_main --> plugins
    tui_app --> event_bus
    cli_main --> plugins
    cli_main --> config

    style event_bus fill:#f96,stroke:#333
    style config fill:#9cf,stroke:#333
    style storage fill:#9c9,stroke:#333
    style process_mgr fill:#fc9,stroke:#333
```

**Cycle detected:** `core.storage` → `core.config` and `core.config` → `core.event_bus` → `core.storage` forms a cycle: `storage → config → event_bus → storage`. This is an **implicit circular dependency** mediated through the global singleton pattern (`get_config()`, `get_event_bus()`, `get_storage()`). No import cycle exists, but the runtime dependency is circular.
