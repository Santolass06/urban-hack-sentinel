# Diagramas de Auditoria - Urban Hack Sentinel
Modelo: gemini_3_1_pro

## 1. Arquitetura de Alto Nível e Fluxo de Dados

Este diagrama ilustra a separação de responsabilidades entre as interfaces de utilizador (UI), o Core (orquestração), os Módulos (lógica de ataque/scanning) e a Camada de Abstração de Hardware (HAL).

```mermaid
graph TD
    subgraph Interfaces
        UI_CLI[CLI - Typer]
        UI_TUI[TUI - Textual]
        UI_API[API - FastAPI/Web]
    end

    subgraph Core
        CBUS[Event Bus]
        CPMG[Process Manager]
        CST[Storage / SQLite]
        CPLG[Plugin System]
    end

    subgraph Modules
        MWIFI[WiFi Attacks/Scan]
        MBLE[BLE / Fast Pair]
        MNET[Network / Vuln]
        MEXP[Exploit Runner]
        MCAM[Camera Discovery]
        MHID[HID / USB Gadget]
    end

    subgraph Abstraction & External
        HWIFI[HAL: WiFi]
        HBLE[HAL: BLE]
        EXTTools[External Tools: nmap, nuclei, msf, reaver]
    end

    UI_CLI --> CBUS
    UI_TUI --> CBUS
    UI_API --> CBUS
    
    CBUS <--> CPLG
    CBUS --> CST
    
    CPLG --> MWIFI
    CPLG --> MBLE
    CPLG --> MNET
    CPLG --> MEXP
    CPLG --> MCAM
    CPLG --> MHID
    
    MWIFI --> HWIFI
    MBLE --> HBLE
    
    MWIFI -.-> CPMG
    MNET -.-> CPMG
    MEXP -.-> CPMG
    
    CPMG --> EXTTools
```

## 2. Grafo de Dependências Internas

Mapeamento de como os pacotes internos se interligam. Destaca-se a forte dependência cruzada entre os módulos (ex: Exploit Runner depende de Network e Metasploit) e a dependência geral do Core.

```mermaid
graph TD
    urban_hs[urban_hs] --> cli
    urban_hs --> ui
    urban_hs --> core
    urban_hs --> modules
    urban_hs --> hal

    cli --> core
    ui --> core
    ui --> modules

    modules --> core
    modules --> hal

    subgraph Modules Internal
        modules.exploit --> modules.network
        modules.exploit --> modules.metasploit
        modules.wifi --> modules.credential
    end
    
    subgraph HAL Internal
        hal.ble --> bleak
        hal.wifi --> scapy
    end
```
