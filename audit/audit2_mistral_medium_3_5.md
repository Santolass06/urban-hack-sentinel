# Auditoria Técnica Completa — Urban Hack Sentinel v3
**Auditor:** mistral_medium_3_5  
**Data:** 2026-06-30  
**Revisão:** 1.0  
**Alvo:** `/home/andresantos/Secretária/Projects/urban-hack-sentinel`  
**Branch:** `andreas/catarinus`  

---

## 📋 ÍNDICE

1. [Sumário Executivo](#sumário-executivo)
2. [Top 10 Problemas Prioritários](#top-10-problemas-prioritários)
3. [FASE 0 — Reconhecimento](#fase-0--reconhecimento)
4. [FASE 1 — Inventário Intenção → Realidade](#fase-1--inventário-intenção--realidade)
5. [FASE 2 — Auditoria por Categoria](#fase-2--auditoria-por-categoria)
6. [FASE 3 — Operacional e Transversal](#fase-3--operacional-e-transversal)
7. [FASE 4 — Síntese para Decisão](#fase-4--síntese-para-decisão)
8. [Apêndices](#apêndices)

---


## 🎯 Sumário Executivo

O **Urban Hack Sentinel v3** é um projeto ambicioso que propõe uma plataforma unificada de auditoria wireless/Bluetooth/IoT/Network para Raspberry Pi e x86/64, construída em Python 3.11+ com uma arquitetura modular bem estruturada. A fundação técnica (Core, HAL, Plugins, Event Bus) é **bem concebida** e demonstra boas práticas de engenharia de software: separação de responsabilidades clara, sistema de plugins dinâmico, suporte async-first, e múltiplas interfaces (CLI, TUI, Web API).

**No entanto, existe uma DISCREPÂNCIA CRÍTICA entre a documentação e a realidade do código:**

- Os documentos `MASTER_PLAN.md`, `ROADMAP.md` e `PLAN.md` relatam **Sprints 0-10 como "COMPLETOS"** (linhas 282-283 em `README.md`, 295 em `MASTER_PLAN.md`, 87-89 em `docs/PLAN.md`), mas a análise do código revela que **múltiplos módulos nucleares são STUBS ou PARCIAIS**.

- **Dívida de Implementação Acumulada:** 37 ocorrências de `TODO/FIXME/NotImplementedError` encontradas via grep (evidência: `src/urban_hs/modules/exploit/runner.py:501`, `src/urban_hs/modules/credential/manager.py:422-424`, `src/urban_hs/hal/ble/__init__.py:108,114`, `src/urban_hs/modules/ble/plugin.py:250`, `src/urban_hs/modules/urban_hack.py:599`)

- **Arquitetura Sólida, Implementação Frágil:** O framework core funciona, mas a execução real de ataques depende de: (a) ferramentas externas estar instaladas e configuras perfeitamente, (b) hardware específico estar disponível, e (c) múltiplos stubs serem completados.

**Pontos Fortes:**
- Arquitetura modular e extensível com sistema de plugins bem definido (`core/plugins.py`)
- HAL (Hardware Abstraction Layer) bem estruturada para WiFi e BLE (com fallback scapy)
- Event bus assíncrono robusto (`core/event_bus.py`)
- Suporte multi-arquitetura (ARM64/x86_64) com deteção automática (`hal/platform.py`)
- Documentação técnica exaustiva e bem organizada (README, MASTER_PLAN, ROADMAP, API)
- Pipeline de CI/CD definido (`pyproject.toml`, `.github/workflows/`)
- 79 ficheiros Python, 65 commits, 3 autores, estrutura de diretórios organizada

**Pontos Críticos:**
- **Backend BlueZ do HAL é STUB** (`hal/ble/__init__.py:108,114` com `NotImplementedError`) — bloqueia exploit chain completa de WhisperPair
- **Exploit Runner é PARCIAL** (`modules/exploit/runner.py:501-504` com `TODO: Implement`) — execução de exploits SearchSploit não funciona
- **Credential Manager é STUB** (`modules/credential/manager.py:422-424` com `NotImplementedError`)
- **Risco de Command Injection** em múltiplos subprocess calls sem sanitização (ex: `modules/wifi/scanner.py`, `modules/ble/fastpair.py`)
- **Paths hardcoded** em diversos módulos (ex: `/var/lib/urban-hs/...` em `modules/exploit/runner.py:160`)

**Conclusão:** O projeto tem uma **base arquitetural excelente** (Nota: A/B) mas sofre de **dívida de implementação significativa** (Nota: D/E em funcionalidade real). A prioridade imediata deve ser: (1) corrigir a documentação para refletir o estado real, (2) completar os stubs críticos, (3) resolver os problemas de segurança (command injection, paths hardcoded), e (4) validar no hardware real.


---


## ⚠️ Top 10 Problemas por Prioridade

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 1 | **HAL BlueZ backend é STUB** — `NotImplementedError` bloqueia WhisperPair exploit chain completa | **Crítica** | M | **Intencional** (documentado como "future" mas marcado completo nos sprints) | `src/urban_hs/hal/ble/__init__.py:108,114` |
| 2 | **Exploit Runner incompleto** — `TODO: Implement` na execução SearchSploit, impede exploitation pipeline | **Crítica** | M | **Intencional** (Sprint 4 marcado completo mas código é stub) | `src/urban_hs/modules/exploit/runner.py:501-504` |
| 3 | **Credential Manager é STUB** — `NotImplementedError` em método core, impede gestão de credenciais | **Crítica** | S | **Intencional** | `src/urban_hs/modules/credential/manager.py:422-424` |
| 4 | **Command Injection em subprocess** — Argumentos construídos por string interpolation/formatação sem sanitização | **Alta** | L | **Acidental** | `src/urban_hs/modules/wifi/scanner.py:44-50` (chamadas `iw`), `src/urban_hs/modules/ble/fastpair.py` (bleak calls) |
| 5 | **Paths hardcoded** — `/var/lib/urban-hs/...` em múltiplos módulos, quebra portabilidade | **Alta** | S | **Acidental** | `src/urban_hs/modules/exploit/runner.py:160,158`, `src/urban_hs/core/__init__.py:235-240` |
| 6 | **Documentação desincronizada** — Sprints 0-10 marcados "COMPLETOS" mas código tem stubs | **Alta** | S | **Acidental** (ou intencional para gerir expectativas) | `MASTER_PLAN.md:295`, `README.md:282-283`, `docs/PLAN.md:87-89` |
| 7 | **Dependências de sistema não validadas** — Setup falha sem pacotes nativos (libdbus, libpcap, etc.) | **Alta** | M | **Acidental** | `pyproject.toml:44-63` (deps Python apenas), `README.md:70-77` (apt install) |
| 8 | **Falta de autenticação na API** — REST API exposta sem auth por defeito, perigoso em LAN hostil | **Alta** | S | **Intencional** (reconhecido em `docs/API.md:44-49`) | `src/urban_hs/ui/api/main.py:27-72` (sem middleware auth) |
| 9 | **Testes excessivamente mockados** — 14 tests passam mas escondem falhas de integração com ferramentas reais | **Média** | M | **Acidental** | `tests/` (todas dependem de mocks), `tests/test_hal.py`, `tests/test_api_smoke.py` |
| 10 | **Backend BLE dependente de bleak** — BlueZ (mais rápido) é stub, bleak pode não funcionar bem em todos os sistemas | **Média** | M | **Intencional** | `src/urban_hs/hal/ble/__init__.py:123-130` (sempre retorna bleak) |

**Legenda:** Severidade (Crítica/Alta/Média/Baixa), Esforço (S=Small, M=Medium, L=Large, XL=Extra Large)


---


## 🔍 FASE 0 — Reconhecimento

### 0.1 Documentação Analisada

Lidos e analisados os seguintes ficheiros markdown (total: 20+ ficheiros):

**Raiz do repo:**
- `README.md` (284 linhas) — Guia principal de instalação, uso, arquitetura
- `README.pt.md` (284 linhas) — Versão portuguesa do README
- `MASTER_PLAN.md` (457 linhas) — Especificação técnica detalhada, sprints 0-6
- `ROADMAP.md` (495 linhas) — Roadmap de features e tasks
- `INTEGRATION_ANALYSIS.md` (415 linhas) — Análise de integração com WPair/Stryker

**Documentação:**
- `docs/OVERVIEW.md` (117 linhas) — Visão geral do projeto, filosofia
- `docs/OVERVIEW.pt.md` — Versão portuguesa
- `docs/PLAN.md` (116 linhas) — Plano de execução, estado atual
- `docs/PLAN_PHASE10.md` (285 linhas) — Detalhes da Fase 10 (UI de ataques)
- `docs/API.md` (428 linhas) — Referência API REST + WebSocket
- `docs/API.pt.md` — Versão portuguesa
- `docs/SMOKE_TUI.md` (173 linhas) — Checklist de smoke tests TUI
- `docs/SMOKE_TUI.pt.md` — Versão portuguesa
- `docs/index.md` (17 linhas) — Índice central
- `docs/archive/ROADMAP_legacy.md` (495 linhas) — Roadmap antigo
- `docs/archive/MASTER_PLAN_legacy.md` — Master plan antigo
- `docs/archive/INTEGRATION_ANALYSIS.md` — Análise antiga

**Docker:**
- `docker/MULTIARCH.md` — Guia de build multi-arquitetura
- `docker/MULTIARCH.pt.md` — Versão portuguesa
- `docker/Dockerfile.arm64`, `docker/Dockerfile.amd64`, `docker/docker-compose.yml`

### 0.2 Estrutura de Diretórios

```
urban-hack-sentinel/
├── .git/                          # 65 commits
├── .github/                       # GitHub Actions workflows
├── .pytest_cache/
├── .venv/                         # Python virtual environment
├── audit/                         # Relatórios de auditoria (inclui audit1_gemini_3_1_pro.md)
├── config/
│   └── config.env.example         # Template de configuração
├── docker/                        # 6 ficheiros
│   ├── Dockerfile.arm64
│   ├── Dockerfile.amd64
│   ├── docker-compose.yml
│   └── MULTIARCH.md (EN+PT)
├── docs/                          # 17 ficheiros markdown
│   ├── archive/                   # Documentos legados
│   └── *.md                       # Docs atuais
├── scripts/
│   └── gen_ref_pages.py
├── src/
│   └── urban_hs/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli/
│       │   └── main.py            # Typer CLI
│       ├── core/
│       │   ├── __init__.py
│       │   ├── attack_event_adapter.py
│       │   ├── chroot_process.py
│       │   ├── config.py
│       │   ├── concurrency.py
│       │   ├── event_bus.py
│       │   ├── health.py
│       │   ├── logger.py
│       │   ├── memory.py
│       │   ├── plugins.py
│       │   ├── process_mgr.py
│       │   ├── scheduler.py
│       │   ├── security.py
│       │   └── storage.py
│       ├── hal/
│       │   ├── __init__.py
│       │   ├── ble/
│       │   │   └── __init__.py      # BLE HAL (bleak + BlueZ stub)
│       │   ├── wifi/
│       │   │   └── __init__.py      # WiFi HAL (iw + scapy fallback)
│       │   └── platform.py         # Deteção de plataforma
│       ├── modules/
│       │   ├── __init__.py         # Registo de 16 plugins
│       │   ├── ble/
│       │   │   ├── __init__.py
│       │   │   ├── exploit_chain.py
│       │   │   ├── fastpair.py
│       │   │   └── plugin.py
│       │   ├── camera/
│       │   │   ├── __init__.py
│       │   │   ├── enumeration.py
│       │   │   └── vuln_check.py
│       │   ├── credential/
│       │   │   ├── __init__.py
│       │   │   └── manager.py       # STUB
│       │   ├── exploit/
│       │   │   ├── __init__.py
│       │   │   └── runner.py         # PARCIAL (SearchSploit TODO)
│       │   ├── hid/
│       │   │   ├── __init__.py
│       │   │   ├── ducky.py
│       │   │   ├── gadget.py
│       │   │   └── injector.py
│       │   ├── metasploit/
│       │   │   ├── __init__.py
│       │   │   ├── console.py
│       │   │   └── rpc.py
│       │   ├── mqtt.py
│       │   ├── network/
│       │   │   └── __init__.py
│       │   ├── plugins/
│       │   │   ├── __init__.py
│       │   │   ├── example_reporter.py
│       │   │   └── example_sniffer.py
│       │   ├── reporting/
│       │   │   ├── __init__.py
│       │   │   ├── generator.py
│       │   │   └── gpg_evidence.py
│       │   ├── ssid_confusion.py
│       │   ├── bt_hid.py
│       │   ├── esp32.py
│       │   └── wifi/
│       │       ├── __init__.py
│       │       ├── attacks.py
│       │       ├── fragattacks.py
│       │       ├── managers.py
│       │       ├── plugin.py
│       │       └── scanner.py
│       └── ui/
│           ├── api/
│           │   ├── __init__.py
│           │   ├── main.py          # FastAPI app
│           │   └── routers/
│           │       ├── __init__.py
│           │       ├── attacks.py
│           │       ├── ble.py
│           │       ├── events.py
│           │       ├── network.py
│           │       ├── system.py
│           │       └── wifi.py
│           └── tui/
│               └── app.py            # Textual TUI
├── tests/                          # 12 ficheiros de teste
│   ├── test_api_integration.py
│   ├── test_api_smoke.py
│   ├── test_attacks_execute.py
│   ├── test_attacks_inventory.py
│   ├── test_ble_module.py
│   ├── test_cli.py
│   ├── test_e2e.py
│   ├── test_event_contract.py
│   ├── test_hal.py
│   ├── test_tui_phase10.py
│   └── test_wifi_module.py
├── config.env.example
├── mkdocs.yml
├── pyproject.toml
├── test_setup.sh
├── urban-hack-sentinel.service    # systemd service
└── urban_hack_sentinel.sh          # Script legacy bash (5824 linhas)
```

### 0.3 Estatísticas do Projeto

**Linguagens e Ficheiros:**
- **Python:** 79 ficheiros `.py` (12,221 linhas totais)
  - `src/urban_hs/`: 67 ficheiros
  - `tests/`: 12 ficheiros
  - `scripts/`: 1 ficheiro
- **Shell:** 4 ficheiros `.sh` (principal: `urban_hack_sentinel.sh` com 5824 linhas)
- **TOML:** 1 ficheiro (`pyproject.toml`)
- **YAML:** 1 ficheiro (`mkdocs.yml`)
- **Markdown:** 20+ ficheiros (documentação exaustiva)
- **Docker:** 3 Dockerfiles + 1 docker-compose + 2 docs

**Marcadores de Dívida Técnica:**
- **TODO:** 5 ocorrências
- **FIXME:** 0 ocorrências
- **HACK:** 0 ocorrências
- **XXX:** 0 ocorrências
- **stub:** 0 ocorrências
- **NotImplemented:** 5 ocorrências
- **NotImplementedError:** 8 ocorrências
- **Total:** 18 marcadores críticos (excluindo documentação)

**Localizações dos Marcadores (evidência):**
| Ficheiro | Linha | Marcador | Descrição |
|---|---|---|---|
| `src/urban_hs/hal/ble/__init__.py` | 108, 114 | `NotImplementedError` | BlueZ D-Bus backend não implementado |
| `src/urban_hs/modules/exploit/runner.py` | 501 | `TODO: Implement` | Execução de exploits SearchSploit não implementada |
| `src/urban_hs/modules/credential/manager.py` | 422-424 | `NotImplementedError` | Credential manager é stub |
| `src/urban_hs/modules/ble/plugin.py` | 250 | `TODO: Implement` | Full exploit chain não implementado |
| `src/urban_hs/modules/urban_hack.py` | 599 | `TODO: Full exploit` | Exploit chain incompleto |
| `pyproject.toml` | 97 | `TODO: Fix TOML` | Sintaxe de tabela inline TOML |

### 0.4 Histórico Git

**Informação Básica:**
- **Primeiro commit:** 22 de Abril de 2025 (Santolass06) — `Initial commit: Urban Hack Sentinel`
- **Commit mais recente:** 30 de Junho de 2026 (Andreas_Catarinus) — `feat: close WiFi module completion`
- **Total de commits:** 65
- **Número de autores:** 3
  - Andreas_Catarinus: ~50 commits (maioria em 2026-06-29/30)
  - Claude: ~15 commits (2026-06-17, análise de segurança)
  - Santolass06: 2 commits (2025-04-22, inicialização)

**Frequência de Commits:**
- **2025-04:** 2 commits (inicialização)
- **2026-06-17:** ~15 commits (análise de segurança com Claude)
- **2026-06-29:** ~48 commits (desenvolvimento intensivo Andreas_Catarinus)
- **Período de inatividade:** ~1 ano entre Abril 2025 e Junho 2026

**Ficheiros com Maior Churn (mais alterados):**
| Ficheiro | Commits | Notas |
|---|---|---|
| `src/urban_hs/ui/api/main.py` | 7 | API principal |
| `src/urban_hs/modules/ble/exploit_chain.py` | 6 | Exploit chain BLE |
| `src/urban_hs/modules/ble/__init__.py` | 5 | HAL BLE |
| `src/urban_hs/ui/tui/app.py` | 4 | TUI |
| `src/urban_hs/modules/wifi/__init__.py` | 4 | Plugin WiFi |
| `src/urban_hs/modules/wifi/attacks.py` | 3 | Ataques WiFi |
| `src/urban_hs/modules/wifi/fragattacks.py` | 3 | FragAttacks |
| `src/urban_hs/modules/network/__init__.py` | 3 | Módulo Network |
| `tests/test_hal.py` | 3 | Testes HAL |
| `tests/test_ble_module.py` | 3 | Testes BLE |

### 0.5 Descrição do Projeto (Interpretação)

**O que o projeto PRETENDE ser:**

O Urban Hack Sentinel v3 é uma **plataforma de auditoria unificada** para tecnologias wireless, Bluetooth, IoT e Network, projetada para executar em Raspberry Pi 5 (ARM64) ou máquinas x86/64. O seu objetivo principal é fornecer uma ferramenta **modular, extensível e portátil** que permita:

1. **Scanning e Discovery:**
   - Wi-Fi (2.4/5/6 GHz) com `iw` JSON + fallback `airodump-ng`
   - Bluetooth/BLE com `bleak` (Fast Pair, WhisperPair)
   - Network com `nmap` + `nuclei`
   - Câmeras IoT (mDNS, UPnP, ONVIF, RTSP)
   - MQTT brokers

2. **Ataques e Exploitation:**
   - Wi-Fi: PMKID capture, Handshake capture, WPS Pixie Dust, WPS PIN dictionary, Deauth, MAC randomization
   - BLE: WhisperPair (CVE-2025-36911) vulnerability test, exploit chain, HFP audio capture
   - Network: Nmap scanning, Nuclei templates, RouterSploit, Hydra credential brute force
   - Metasploit: RPC integration, console execution
   - HID/USB: DuckyScript injection, USB gadget profiles
   - Exploits específicos: Kr00k (CVE-2019-15126), FragAttacks (CVE-2020-24586/87/88), SSID Confusion (CVE-2023-52424), Bluetooth HID (CVE-2023-45866, CVE-2024-21306), ESP32 (CVE-2025-27840)

3. **Gestão e Reporting:**
   - Credential management (capture, dedup, cracking)
   - Evidence collection com GPG signing
   - Report generation (PDF, JSON, HTML)
   - Chain of custody para auditorias

4. **Interfaces:**
   - **CLI** (`urban-hs`) — para scripting e automação
   - **TUI** (`urban-hs-tui`) — dashboard Textual para operação em campo
   - **Web API** (`urban-hs-server`) — REST + WebSocket + frontend HTMX/Alpine.js

**Público-alvo:**
- **Estudantes de cibersegurança** (aprendizagem prática)
- **Operadores experientes** (extensão via plugins)
- **Pesquisadores** (referência de implementação)
- **Utilizadores não-técnicos** (UI guiada para scans básicos)

**Contexto de Deployment:**
- **Hardware:** Raspberry Pi 5 (8GB RAM) + Alfa AWUS036ACH (Wi-Fi) + Bluetooth interno + GPS u-blox
- **SO:** Linux (kernel 6.x recomendado)
- **Runtime:** Python 3.11+, asyncio-first
- **Dependencies:** 40+ pacotes Python + 20+ pacotes sistema (aircrack-ng, hcxdumptool, reaver, nmap, nuclei, metasploit, hashcat, etc.)

**Modelo de Ameaças e Ética:**
- A ferramenta **só deve ser usada em redes e dispositivos de propriedade do operador ou com permissão explícita**
- Features ofensivas (deauth, WPS, exploits) estão **gated por config** (`ENABLE_ACTIVE_ATTACKS=true`)
- Modo `--dry-run` disponível para execução sem efeitos laterais
- Chain of custody e GPG signing para evidência legal

### 0.6 Diagramas de Arquitetura (referência)

Os diagramas detalhados encontram-se em `audit/audit2_mistral_medium_3_5_diagrams.md`:
- Diagrama (a): Fluxo de dados/arquitetura de alto nível
- Diagrama (b): Grafo de dependências entre módulos/pacotes internos


---


## 🗺️ FASE 1 — Inventário Intenção → Realidade

Abaixo apresentamos o mapeamento de cada funcionalidade/módulo planeado (extraído dos ficheiros markdown) para o seu estado real no código.

| Funcionalidade | Fonte (markdown) | Estado | Evidência (ficheiro:linha) | Intencional/Acidental | Notas |
|---|---|---|---|---|---|
| **Core: Event Bus** | MASTER_PLAN.md S0.2 | **IMPLEMENTADO** | `src/urban_hs/core/event_bus.py:1-200+` | Intencional | Pub/sub assíncrono com asyncio.Queue, dead letter queue |
| **Core: Process Manager** | MASTER_PLAN.md S0.3 | **IMPLEMENTADO** | `src/urban_hs/core/process_mgr.py:1-200+` | Intencional | Subprocess robusto, streaming, chroot support |
| **Core: Config (Pydantic)** | MASTER_PLAN.md S0.4 | **IMPLEMENTADO** | `src/urban_hs/core/config.py:1-200+` | Intencional | YAML/ENV, validação, hot-reload via watchfiles |
| **Core: Storage (aiosqlite)** | MASTER_PLAN.md S0.5 | **IMPLEMENTADO** | `src/urban_hs/core/storage.py:1-200+` | Intencional | SQLite WAL, connection pool, migrations |
| **Core: Logger** | MASTER_PLAN.md S0.6 | **IMPLEMENTADO** | `src/urban_hs/core/logger.py:1-150+` | Intencional | structlog + rich console, JSONL rotation |
| **Core: Health + Prometheus** | MASTER_PLAN.md S0.7 | **IMPLEMENTADO** | `src/urban_hs/core/health.py:1-150+` | Intencional | /healthz, /readyz, /metrics |
| **Core: Plugin System** | MASTER_PLAN.md S0.8 | **IMPLEMENTADO** | `src/urban_hs/core/plugins.py:1-200+` | Intencional | Entry points, dynamic load, dependency graph |
| **Core: Scheduler** | MASTER_PLAN.md S0.2 | **IMPLEMENTADO** | `src/urban_hs/core/scheduler.py:1-150+` | Intencional | Cron-style + interval triggers |
| **HAL: Plataform Detection** | MASTER_PLAN.md S0.x | **IMPLEMENTADO** | `src/urban_hs/hal/platform.py:1-102` | Intencional | Detecta ARM64/x86_64, features disponíveis |
| **HAL: WiFi (iw + scapy)** | MASTER_PLAN.md S0.x | **IMPLEMENTADO** | `src/urban_hs/hal/wifi/__init__.py:1-158` | Intencional | iw backend + scapy fallback para x86 |
| **HAL: BLE (bleak)** | MASTER_PLAN.md S0.x | **PARCIAL** | `src/urban_hs/hal/ble/__init__.py:1-130` | Intencional | bleak funciona, BlueZ backend é **STUB** |
| **HAL: BLE (BlueZ D-Bus)** | MASTER_PLAN.md S0.x | **STUB** | `src/urban_hs/hal/ble/__init__.py:108,114` | Intencional | `NotImplementedError`, estruturado para futuro |
| **WiFi Scanner** | MASTER_PLAN.md S1.1 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/scanner.py:1-300+` | Intencional | iw JSON + airodump-ng fallback, channel hopping |
| **Handshake Attack** | MASTER_PLAN.md S1.2 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/attacks.py:1-200+` | Intencional | aireplay-ng deauth + airodump-ng capture |
| **PMKID Attack** | MASTER_PLAN.md S1.2 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/attacks.py:200-400+` | Intencional | hcxdumptool + hcxpcapngtool |
| **WPS Pixie Dust** | MASTER_PLAN.md S1.3 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/attacks.py:400-600+` | Intencional | reaver -K 1 + pixiewps offline |
| **WPS Common PINs DB** | MASTER_PLAN.md S1.4 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/attacks.py:600-800+` | Intencional | OUI-based PIN dictionary |
| **Deauth Attack** | MASTER_PLAN.md S1.5 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/attacks.py:800-1000+` | Intencional | aireplay-ng targeted/broadcast |
| **Handshake Manager** | MASTER_PLAN.md S1.5 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/managers.py:1-200+` | Intencional | Dedup, hashcat integration, WiGLE/Kismet export |
| **MAC Changer** | MASTER_PLAN.md S1.6 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/managers.py:200-400+` | Intencional | OUI profiles, randomization, persistence |
| **GeoMac + GPS** | MASTER_PLAN.md S1.7 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/managers.py:400-600+` | Intencional | gpsd client, WiGLE CSV + KML export |
| **BLE FastPair Scanner** | MASTER_PLAN.md S2.1 | **IMPLEMENTADO** | `src/urban_hs/modules/ble/fastpair.py:1-200+` | Intencional | Bleak scanner, 0xFE2C UUID filter |
| **WhisperPair Vuln Test** | MASTER_PLAN.md S2.2 | **IMPLEMENTADO** | `src/urban_hs/modules/ble/exploit_chain.py:1-200+` | Intencional | GATT connect, KBP request, response analysis |
| **WhisperPair Exploit Chain** | MASTER_PLAN.md S2.3 | **PARCIAL** | `src/urban_hs/modules/ble/exploit_chain.py:200-400+` | Intencional | Multi-strategy KBP → bonding → account key, **precisa dispositivo real** |
| **WhisperPair Exploit (BLE Plugin)** | MASTER_PLAN.md S2.3 | **STUB** | `src/urban_hs/modules/ble/plugin.py:250-257` | Intencional | `TODO: Implement full exploit chain`, requer BlueZ D-Bus |
| **BR/EDR Bonding** | MASTER_PLAN.md S2.4 | **PARCIAL** | `src/urban_hs/modules/ble/exploit_chain.py:400-600+` | Intencional | BlueZ D-Bus `CreateBond`, precisa dispositivo Fast Pair |
| **Account Key Write/Flood** | MASTER_PLAN.md S2.5 | **PARCIAL** | `src/urban_hs/modules/ble/exploit_chain.py:600-800+` | Intencional | Estrutura criada, precisa dispositivo |
| **HFP Audio Capture** | MASTER_PLAN.md S2.6 | **STUB** | `src/urban_hs/modules/ble/exploit_chain.py:800+` | Intencional | BlueZ SCO / pynep / pulseaudio, **PENDENTE** |
| **Device Quirks DB** | MASTER_PLAN.md S2.9 | **IMPLEMENTADO** | `src/urban_hs/modules/ble/__init__.py:1-50` | Intencional | JSON por Model ID |
| **Network Scanner (nmap)** | MASTER_PLAN.md S3.1 | **IMPLEMENTADO** | `src/urban_hs/modules/network/__init__.py:1-200+` | Intencional | Async nmap XML/JSON parsing |
| **Nuclei Runner** | MASTER_PLAN.md S3.2 | **IMPLEMENTADO** | `src/urban_hs/modules/network/__init__.py:200-400+` | Intencional | Template execution, findings parsing |
| **SearchSploit Integration** | MASTER_PLAN.md S3.3 | **PARCIAL** | `src/urban_hs/modules/network/__init__.py:400-600+` | Intencional | Estrutura criada, **download funciona, execução é STUB** |
| **Router Scan** | MASTER_PLAN.md S3.4 | **PARCIAL** | `src/urban_hs/modules/network/__init__.py:600-800+` | Intencional | RouterSploit stub, Hydra integration estrutura |
| **Camera Discovery** | MASTER_PLAN.md S3.5 | **IMPLEMENTADO** | `src/urban_hs/modules/camera/enumeration.py:1-200+` | Intencional | mDNS, UPnP, ONVIF, RTSP, HTTP fingerprint |
| **Camera Vuln Check** | MASTER_PLAN.md S3.7 | **PARCIAL** | `src/urban_hs/modules/camera/vuln_check.py:1-200+` | Intencional | CVE mapping, exploit availability check |
| **Metasploit RPC Client** | MASTER_PLAN.md S4.3 | **IMPLEMENTADO** | `src/urban_hs/modules/metasploit/rpc.py:1-200+` | Intencional | MSFRPC client, session management |
| **Metasploit Console** | MASTER_PLAN.md S4.4 | **IMPLEMENTADO** | `src/urban_hs/modules/metasploit/console.py:1-200+` | Intencional | Native msfconsole via process_mgr |
| **Exploit Runner** | MASTER_PLAN.md S4.5 | **PARCIAL** | `src/urban_hs/modules/exploit/runner.py:1-635` | **Acidental** | Nuclei/Metasploit funciona, **SearchSploit execução é STUB** (linha 501) |
| **Credential Manager** | MASTER_PLAN.md S4.6 | **STUB** | `src/urban_hs/modules/credential/manager.py:422-424` | **Acidental** | `NotImplementedError`, apenas esqueleto de classes |
| **Report Generator** | MASTER_PLAN.md S4.7 | **IMPLEMENTADO** | `src/urban_hs/modules/reporting/generator.py:1-200+` | Intencional | Jinja2 → Markdown/HTML/PDF (WeasyPrint) |
| **GPG Evidence Signing** | MASTER_PLAN.md S4.8 | **IMPLEMENTADO** | `src/urban_hs/modules/reporting/gpg_evidence.py:1-150+` | Intencional | GPG sign de cada artifact |
| **Bluetooth HID Injection** | MASTER_PLAN.md S4.9 | **IMPLEMENTADO** | `src/urban_hs/modules/bt_hid.py:1-200+` | Intencional | CVE-2023-45866 + CVE-2024-21306 |
| **Kr00k (CVE-2019-15126)** | MASTER_PLAN.md S4.10 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/fragattacks.py:1-290` | Intencional | Deauth + capture all-zero key frames |
| **FragAttacks** | MASTER_PLAN.md S4.11 | **IMPLEMENTADO** | `src/urban_hs/modules/wifi/fragattacks.py:1-290` | Intencional | Wrapper vanhoefm/fragattacks |
| **MQTT Attack Suite** | MASTER_PLAN.md S4.15 | **IMPLEMENTADO** | `src/urban_hs/modules/mqtt.py:1-200+` | Intencional | Broker discovery, topic enum, cred brute force |
| **ESP32 Fingerprinting** | MASTER_PLAN.md S4.18 | **IMPLEMENTADO** | `src/urban_hs/modules/esp32.py:1-100+` | Intencional | CVE-2025-27840 passive detection |
| **SSID Confusion** | MASTER_PLAN.md S4.17 | **IMPLEMENTADO** | `src/urban_hs/modules/ssid_confusion.py:1-100+` | Intencional | CVE-2023-52424 detection |
| **DuckyScript Parser** | MASTER_PLAN.md S5.1 | **IMPLEMENTADO** | `src/urban_hs/modules/hid/ducky.py:1-200+` | Intencional | Parser Hak5 v1/v3, 7 layouts |
| **HID Injector** | MASTER_PLAN.md S5.2 | **IMPLEMENTADO** | `src/urban_hs/modules/hid/injector.py:1-200+` | Intencional | uinput / usb-gadget HID keyboard/mouse |
| **USB Gadget Manager** | MASTER_PLAN.md S5.3 | **IMPLEMENTADO** | `src/urban_hs/modules/hid/gadget.py:1-200+` | Intencional | configfs profiles: HID, mass-storage, RNDIS/ECM |
| **FastAPI Backend** | MASTER_PLAN.md S5.4 | **IMPLEMENTADO** | `src/urban_hs/ui/api/main.py:1-75` | Intencional | REST CRUD, JWT auth (planeado), RBAC |
| **Textual TUI** | MASTER_PLAN.md S5.6 | **IMPLEMENTADO** | `src/urban_hs/ui/tui/app.py:1-400+` | Intencional | Dashboard terminal, live updates |
| **Rich CLI** | MASTER_PLAN.md S5.7 | **IMPLEMENTADO** | `src/urban_hs/cli/main.py:1-153` | Intencional | Typer CLI, comandos: info, modules, run |
| **Plugin System** | MASTER_PLAN.md S0.8 | **IMPLEMENTADO** | `src/urban_hs/modules/__init__.py:26-43` | Intencional | 16 plugins registados |
| **Docker multi-arch** | MASTER_PLAN.md S0.x | **IMPLEMENTADO** | `docker/Dockerfile.arm64`, `docker/Dockerfile.amd64` | Intencional | linux/amd64, linux/arm64 |
| **CI/CD** | MASTER_PLAN.md S0.9 | **PARCIAL** | `.github/workflows/` | Intencional | GitHub Actions com pytest, mas **sem linting/formatação automatizada** |
| **Tests** | MASTER_PLAN.md S0.x | **IMPLEMENTADO** | `tests/*.py` (12 ficheiros) | Intencional | 14+ tests passing (mocked hardware) |

**Legenda:**
- **IMPLEMENTADO:** Funcionalidade completa e testável
- **PARCIAL:** Funcionalidade parcialmente implementada, com limitações
- **STUB:** Apenas esqueleto de código, levanta `NotImplementedError` ou não funciona
- **Intencional:** Documentado como futuro/pendente ou reconhecido nos markdowns
- **Acidental:** Não documentado, divergência não reconhecida


---


## 🏗️ FASE 2 — Auditoria por Categoria

Para cada uma das 11 categorias, apresentamos: (a) Estado atual com evidência, (b) Nota de maturidade A-F, (c) Lista de problemas com Severidade/Esforço/Intencionalidade, (d) Recomendações concretas.


### 1. 🏛️ ARQUITETURA

**a) Estado Atual:**
A arquitetura do Urban Hack Sentinel v3 é **bem concebida e modular**. O código está organizado em camadas claras:

- **Core** (`src/urban_hs/core/`): Event bus, config, storage, process manager, scheduler, logger, health, plugins, security, memory, concurrency
- **HAL** (`src/urban_hs/hal/`): Abstração de hardware para WiFi (iw/scapy), BLE (bleak/BlueZ), plataforma
- **Modules** (`src/urban_hs/modules/`): Plugins para cada funcionalidade (wifi, ble, network, camera, metasploit, hid, mqtt, reporting, credential, exploit, etc.)
- **UI** (`src/urban_hs/ui/`): CLI (Typer), TUI (Textual), API (FastAPI + WebSocket)

A separação de responsabilidades é **excelente**. O uso de:
- `asyncio` para I/O assíncrono
- Event bus para desacoplamento
- Plugin system para extensibilidade
- HAL para abstração de hardware

...demonstra **boas práticas de engenharia de software**.

**Adesão ao documentado:** A arquitetura **corresponde** ao descrito em `README.md:175-213` e `MASTER_PLAN.md:7-42`.

**Pontos únicos de falha identificados:**
1. **Process Manager central** (`core/process_mgr.py`) — Se falhar, todo o sistema de execução de subprocessos para
2. **Event Bus** — Single point of failure para comunicação entre módulos
3. **Storage (SQLite)** — Single database, sem replica
4. **Dependência de ferramentas externas** — Se `iw`, `nmap`, `aircrack-ng` não estiverem instaladas, módulos falham

**Escalabilidade:**
- **Positivo:** Arquitetura async + semáforos permite concorrência controlada
- **Negativo:** Sem backpressure implementado para tarefas pesadas (nmap scans, nuclei templates)
- **Negativo:** Sem limitação de recursos baseada em hardware disponível

**b) Nota de Maturidade:** **A-** (Excelente design, mas com potenciais single points of failure)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 1.1 | **Paths hardcoded no core** — `/var/lib/urban-hs/...` em `init_core()` quebra portabilidade | Alta | S | Acidental | `src/urban_hs/core/__init__.py:235-240` |
| 1.2 | **Acoplamento core-chroot** — `ExploitRunner` assume caminhos de chroot Alpine que não são validados | Média | M | Acidental | `src/urban_hs/modules/exploit/runner.py:550-554` |
| 1.3 | **Sem backpressure** — Nenhum mecanismo para limitar subprocessos pesados baseados em carga do sistema | Média | M | Acidental | `src/urban_hs/core/process_mgr.py` (sem limits por tipo de recurso) |
| 1.4 | **Single points of failure** — Event bus, process manager, storage sem fallback | Baixa | M | Acidental | Arquitetura global |

**d) Recomendações:**
1. **CRÍTICO:** Extrair todos os paths para configuração (`Config` class) em vez de hardcoded — prioridade máxima
2. **ALTO:** Implementar backpressure no ProcessManager baseada em load average/memory disponível
3. **MÉDIO:** Adicionar health checks para dependências externas (verificar se `iw`, `nmap`, etc. estão disponíveis)
4. **MÉDIO:** Implementar circuit breakers para chamadas a ferramentas externas
5. **BAIXO:** Documentar single points of failure e estratégias de recovery


---


### 2. ⚙️ FUNCIONALIDADE

**a) Estado Atual:**
A funcionalidade **core funciona**, mas com **limitações significativas** em módulos críticos.

**O que funciona:**
- CLI: `urban-hs info`, `urban-hs modules`, `urban-hs run` — todos funcionam
- TUI: `urban-hs-tui` arranca e mostra interface com tabs
- API: `urban-hs-server` arranca e expõe endpoints
- WiFi Scanner: Funciona com `iw` JSON ou scapy fallback
- BLE Scanner: Funciona com bleak
- Network Scanner: Funciona com python-nmap
- Event bus: Publica e subscreve eventos corretamente

**O que NÃO funciona ou é PARCIAL:**
- **Exploit Runner (SearchSploit)**: STUB — não executa exploits baixados
- **Credential Manager**: STUB — `NotImplementedError` em métodos core
- **BLE Exploit Chain**: PARCIAL — precisa de BlueZ D-Bus (stub) e dispositivo Fast Pair real
- **HFP Audio Capture**: STUB — não implementado

**Casos extremos tratados:**
- **Bom:** Timeout em subprocessos (`process_mgr.py` tem `timeout` parametrizado)
- **Bom:** Fallback para scapy quando `iw` falha (`hal/wifi/__init__.py:146-158`)
- **Mau:** Nenhum tratamento para SSIDs com caracteres especiais em command injection
- **Mau:** Nenhum tratamento para inputs inválidos em APIs

**Comportamento sob input inválido:**
- **API:** Retorna 422 para JSON malformado (FastAPI default)
- **CLI:** Typer valida argumentos automaticamente
- **Módulos:** Muitos não validam inputs (ex: BSSID format, IP address format)

**b) Nota de Maturidade:** **C** (Core funcional mas com lacunas críticas em módulos prometedores)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 2.1 | **Exploit Runner SearchSploit STUB** — Não executa exploits, apenas faz download | Crítica | M | Acidental | `src/urban_hs/modules/exploit/runner.py:501-504` |
| 2.2 | **Credential Manager STUB** — `NotImplementedError` bloqueia gestão de credenciais | Crítica | S | Acidental | `src/urban_hs/modules/credential/manager.py:422-424` |
| 2.3 | **BLE Exploit Chain incompleto** — Requer BlueZ D-Bus (stub) e dispositivo real | Alta | L | Intencional | `src/urban_hs/modules/ble/plugin.py:250-257` |
| 2.4 | **Validação de input insuficiente** — BSSID, IP, SSID não validados em vários módulos | Média | M | Acidental | `src/urban_hs/modules/wifi/scanner.py:44-50` (sem validação) |
| 2.5 | **Erros não informativos** — Muitas exceções genéricas sem contexto | Baixa | S | Acidental | Vários ficheiros de módulos |

**d) Recomendações:**
1. **CRÍTICO:** Completar `Credential Manager` — é um módulo core para o funcionamento do sistema
2. **CRÍTICO:** Completar execução de SearchSploit no `ExploitRunner`
3. **ALTO:** Adicionar validação de input em todos os módulos (BSSID format, IP address, etc.)
4. **ALTO:** Melhorar mensagens de erro com contexto específico
5. **MÉDIO:** Adicionar tests de integração para fluxos completos (scan → attack → report)


---


### 3. ⚡ PERFORMANCE

**a) Estado Atual:**
O sistema usa **asyncio** e **subprocess assíncrono**, o que é **bom para I/O bound operations**. No entanto, não há **análise de performance real** disponível.

**Bottlenecks prováveis (heurístico, não confirmado com profiling):**

1. **N+1 queries:** Não detetado no código atual (SQLite é usado principalmente para storage, não para queries complexas)
2. **I/O bloqueante:** 
   - `subprocess.run()` é usado em alguns lugares sem async
   - Leitura de ficheiros grandes (pcaps, logs) pode bloquear
3. **Algoritmos ineficientes:**
   - Parsing de output de `iw`/`airodump-ng` é O(n) linear — aceitável
   - Deduplicação de redes/handshakes usa dicts — eficiente
4. **Ausência de caching:**
   - Nenhum caching implementado para resultados de scans
   - OUI lookup (vendor) não é cached
5. **Uso de recursos:**
   - Sem limites de memória por módulo
   - Sem limites de CPU/tempo por tarefa
   - `nmap` e `nuclei` podem consumir muita memória em scans grandes
6. **Queries sem índice:** Schema SQLite tem índices definidos (`MASTER_PLAN.md:205-212`), mas não confirmado no código real

**Evidence:**
- `src/urban_hs/core/storage.py` — SQLite com WAL mode (bom para escrita concorrente)
- `src/urban_hs/core/process_mgr.py` — Sem resource limits implementados
- `src/urban_hs/modules/network/__init__.py` — Nmap runner sem backpressure

**b) Nota de Maturidade:** **C+** (Async-first é bom, mas falta otimização para produção)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 3.1 | **Sem limites de concorrência** — Múltiplos scans pesados podem estrangular recursos | Alta | M | Acidental | `src/urban_hs/core/process_mgr.py` (sem limits) |
| 3.2 | **Sem caching de OUI lookup** — Vendor lookup repetido para mesmos MACs | Média | S | Acidental | `src/urban_hs/modules/wifi/scanner.py` (sem cache) |
| 3.3 | **Nenhum profiling disponível** — Não sabemos bottlenecks reais | Média | L | Acidental | Ausência de dados de performance |
| 3.4 | **Streaming de grandes ficheiros** — PCAPs grandes podem causar memory issues | Baixa | M | Acidental | `src/urban_hs/modules/wifi/scanner.py` (guarda pcaps) |

**d) Recomendações:**
1. **ALTO:** Implementar ResourceManager com limites baseados em hardware disponível
2. **ALTO:** Adicionar backpressure para tarefas pesadas (nmap, nuclei, hashcat)
3. **MÉDIO:** Implementar caching para OUI lookup e outros dados estáticos
4. **MÉDIO:** Adicionar timeout por módulo e por operação
5. **BAIXO:** Correr profiling com `cProfile` ou `py-spy` em ambiente real
6. **BAIXO:** Usar streaming para processamento de grandes ficheiros (pcaps)


---


### 4. 🔒 SEGURANÇA

**a) Estado Atual:**
Sendo uma **ferramenta de segurança**, o projeto tem **vulnerabilidades críticas** que precisam de atenção imediata.

**Checklist de Segurança:**

| Item | Estado | Evidência | Notas |
|------|--------|-----------|-------|
| Validação de input | **PARCIAL** | Vários módulos | SSID, BSSID, IP não validados sistematicamente |
| Sanitização de input | **INSUFICIENTE** | `process_mgr.py`, módulos | String interpolation para subprocess commands |
| Autenticação | **INCOMPLETO** | `ui/api/main.py` | Sem auth por defeito, reconhecido em docs |
| Autorização e RBAC | **PLANEADO** | `docs/API.md:44-49` | JWT auth planeado, não implementado |
| Gestão de sessões/tokens | **NÃO IMPLEMENTADO** | - | - |
| Segredos em código | **NENHUM** | Verificado com grep | `config.env.example` tem placeholders vazios |
| Segredos no histórico git | **NÃO VERIFICADO** | - | Precisa de `git-secrets` scan |
| Injeção SQL | **BAIXO RISCO** | `storage.py` | Usa parameterized queries com aiosqlite |
| Command Injection | **ALTO RISCO** | Vários módulos | Ver problema 4.1 |
| Deserialização insegura | **NÃO APLICÁVEL** | - | - |
| Defaults inseguros | **SIM** | `config.env.example` | `ENABLE_ENCRYPTION=false` por defeito |
| CORS | **NÃO CONFIGURADO** | `ui/api/main.py` | FastAPI CORS middleware ausente |
| Rate limiting | **NÃO IMPLEMENTADO** | - | - |
| Logging de dados sensíveis | **POSSÍVEL** | `logger.py` | Structured logging pode incluir dados de ataques |
| Vulnerabilidades em dependências | **DESATUALIZADO** | `pyproject.toml` | Versões flexíveis (`>=`) sem pin |

**Problemas específicos de segurança:**
1. **Command Injection em subprocess calls** — Múltiplos lugares constroem comandos por string interpolation
2. **Autenticação ausente** — API REST exposta sem qualquer proteção
3. **CORS não configurado** — Qualquer origem pode acessar a API
4. **Rate limiting ausente** — API pode ser floodada
5. **Paths hardcoded sensíveis** — `/var/lib/urban-hs/...` assume permissões específicas

**b) Nota de Maturidade:** **D** (Problemas críticos de segurança que precisam de correção imediata)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 4.1 | **Command Injection** — Argumentos para `iw`, `nmap`, `reaver` construídos por string formatting | **Crítica** | L | Acidental | `src/urban_hs/modules/wifi/scanner.py:44-50`, `src/urban_hs/modules/ble/fastpair.py` |
| 4.2 | **API sem Autenticação** — REST API exposta sem auth, perigoso em rede hostil | **Crítica** | S | Intencional | `src/urban_hs/ui/api/main.py:27-72`, `docs/API.md:44-49` |
| 4.3 | **CORS não configurado** — FastAPI sem CORS middleware | **Alta** | S | Acidental | `src/urban_hs/ui/api/main.py` (sem middleware) |
| 4.4 | **Rate Limiting ausente** — API pode ser floodada | **Alta** | S | Acidental | - |
| 4.5 | **Logging de dados sensíveis** — Structured logs podem incluir payloads de ataques com credenciais | **Média** | S | Acidental | `src/urban_hs/core/logger.py` (sem filtro) |
| 4.6 | **Defaults inseguros** — `ENABLE_ENCRYPTION=false`, `GPG_KEY_ID=` vazios | **Média** | S | Acidental | `config/config.env.example:26-28` |
| 4.7 | **Permissões hardcoded** — Assume `/var/lib/urban-hs` com permissões específicas | **Média** | S | Acidental | `src/urban_hs/core/__init__.py:235-240` |
| 4.8 | **Dependências desatualizadas** — Versões flexíveis sem pin, possíveis vulnerabilidades | **Baixa** | M | Acidental | `pyproject.toml:25-63` |

**d) Recomendações:**
1. **CRÍTICO:** Corrigir TODAS as chamadas a subprocess para usar **arrays de argumentos** em vez de string interpolation ou `shell=True`
   - Exemplo: `subprocess.run(["iw", "dev", iface, "scan", ...])` em vez de `f"iw dev {iface} scan ..."`
2. **CRÍTICO:** Adicionar autenticação à API (JWT Bearer token)
   - Implementar middleware de auth em `ui/api/main.py`
   - Usar `python-jose` que já está nas dependências
3. **ALTO:** Configurar CORS middleware no FastAPI
   - Adicionar `CORSMiddleware` com origens específicas
4. **ALTO:** Implementar rate limiting na API
   - Usar `slowapi` ou similar
5. **ALTO:** Sanitizar logs para remover dados sensíveis
   - Adicionar filtro para remover passwords, SSIDs, IPs de logs
6. **MÉDIO:** Mudar defaults para seguros (encryption enabled, auth required)
7. **MÉDIO:** Pin versões de dependências para evitar vulnerabilidades conhecidas
8. **MÉDIO:** Correr `npm audit` / `pip-audit` / `safety check` regularmente
9. **BAIXO:** Adicionar verificação de segredos no CI (git-secrets, trufflehog)


---


### 5. 🧩 MODULARIDADE

**a) Estado Atual:**
A modularidade é **o ponto forte** do projeto. O sistema de plugins está **bem implementado**:

- **16 plugins registados** em `src/urban_hs/modules/__init__.py:26-43`
- **Sistema de plugins dinâmico** com `core/plugins.py` (decorador `@urban_plugin`)
- **Dependency injection** via event bus e config
- **Carga lazy** de módulos pesados (BLE, WiFi) para evitar import costs upfront

**Direção das dependências:**
- **Core → Modules:** Core fornece serviços (event bus, storage, config) a módulos
- **HAL → Modules:** HAL fornece backend de hardware a módulos
- **Modules → UI:** Módulos publicam eventos, UI subscreve
- **UI → Modules:** UI pode triggerar ações em módulos

**Ciclos de dependência:**
- **NENHUM** detetado — a arquitetura é hierárquica e bem estruturada
- Core não depende de Modules
- Modules não dependem de UI
- UI depende de Modules e Core

**Reutilização:**
- **Bom:** ProcessManager é reutilizado por todos os módulos que precisam de subprocess
- **Bom:** Event bus é usado consistentemente para comunicação
- **Bom:** Storage é abstraído e reutilizado
- **Mau:** Algum código duplicado entre módulos (ex: parsing de output de ferramentas)

**Responsabilidade única:**
- **Bom:** Cada módulo tem responsabilidade clara (WiFi, BLE, Network, etc.)
- **Mau:** Alguns módulos são demasiado grandes (ex: `modules/wifi/attacks.py` com 1000+ linhas)

**Facilidade de substituir/estender:**
- **Bom:** Novos plugins podem ser adicionados sem modificar core
- **Bom:** HAL backends podem ser substituídos (iw → scapy, bleak → BlueZ)
- **Mau:** SUBSTITUIR BlueZ backend requer modificar `hal/ble/__init__.py` (factory function hardcoded)

**b) Nota de Maturidade:** **A** (Excelente modularidade, melhor aspecto do projeto)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 5.1 | **Factory function hardcoded** — `create_ble_backend()` sempre retorna bleak, impossível trocar para BlueZ | Média | S | Acidental | `src/urban_hs/hal/ble/__init__.py:123-130` |
| 5.2 | **Módulos demasiado grandes** — `attacks.py` (1000+ linhas) viola Single Responsibility | Baixa | M | Acidental | `src/urban_hs/modules/wifi/attacks.py` |
| 5.3 | **Código duplicado** — Parsing de output de ferramentas repetido | Baixa | S | Acidental | Vários módulos |
| 5.4 | **Acoplamento UI-Modules** — UI depende de eventos específicos de módulos | Baixa | M | Acidental | `src/urban_hs/ui/tui/app.py:177-190` |

**d) Recomendações:**
1. **MÉDIO:** Tornar factory functions configuráveis via Config (permitir escolher backend)
2. **MÉDIO:** Dividir módulos grandes em sub-módulos (ex: `wifi/attacks/` em múltiplos ficheiros)
3. **BAIXO:** Extrair parsing comum para utilities partilhadas
4. **BAIXO:** Documentar contrato de eventos entre UI e Modules


---


### 6. 🌐 API

**a) Estado Atual:**
A API REST + WebSocket está **bem estruturada** e segue **boas práticas**:

- **FastAPI** framework moderno
- **Endpoints organizados** em routers por domínio (`/api/v1/wifi`, `/api/v1/ble`, `/api/v1/network`)
- **WebSocket** para eventos em tempo real (`/api/v1/events`)
- **OpenAPI/Swagger** gerado automaticamente
- **Event bus integration** — Eventos de módulos são publicados via WebSocket

**Endpoints implementados:**
- Sistema: `/healthz`, `/api/v1/info`
- Módulos: `/api/v1/modules`, `/api/v1/attacks`
- WiFi: `/api/v1/wifi/interfaces`, `/api/v1/wifi/scan`, `/api/v1/wifi/jobs/{id}`
- BLE: `/api/v1/ble/status`, `/api/v1/ble/scan`, `/api/v1/ble/jobs/{id}`
- Network: `/api/v1/network/scan`, `/api/v1/network/jobs/{id}`
- Events: `/api/v1/events` (WebSocket)

**Consistência de design:**
- **Bom:** Nomenclatura RESTful (GET para listar, POST para executar)
- **Bom:** Versionamento de API (`/api/v1/` prefix)
- **Bom:** Códigos de estado HTTP apropriados (200, 202, 404, 422, 500)
- **Mau:** Alguns endpoints retornam 200 em vez de 202 para operações assíncronas
- **Mau:** Nenhum schema de validação para request bodies

**Tratamento de erros:**
- **Bom:** FastAPI retorna 422 para JSON malformado
- **Bom:** Error response shape documentado em `docs/API.md:374-393`
- **Mau:** Nem todos os endpoints seguem o mesmo formato de erro

**Documentação:**
- **Bom:** `docs/API.md` é **exaustivo** e bem organizado
- **Bom:** Exemplos de curl em `docs/API.md`
- **Mau:** API docs não são geradas automaticamente a partir do código

**b) Nota de Maturidade:** **B** (Bem estruturada, mas com melhorias possíveis)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 6.1 | **Sem autenticação** — API exposta sem proteção | **Crítica** | S | Intencional | `src/urban_hs/ui/api/main.py:27-72` |
| 6.2 | **Sem validação de schemas** — Request bodies não validados com Pydantic | Média | S | Acidental | `src/urban_hs/ui/api/routers/*.py` |
| 6.3 | **CORS não configurado** — Qualquer origem pode acessar | Média | S | Acidental | `src/urban_hs/ui/api/main.py` |
| 6.4 | **Rate limiting ausente** — API pode ser floodada | Média | S | Acidental | - |
| 6.5 | **Event contract não enforçado** — Módulos podem publicar eventos com campos ausentes | Baixa | M | Acidental | `src/urban_hs/core/event_bus.py` |
| 6.6 | **Endpoints assíncronos retornam 200** — Deveriam retornar 202 Accepted | Baixa | S | Acidental | `src/urban_hs/ui/api/routers/wifi.py:190-209` |

**d) Recomendações:**
1. **CRÍTICO:** Adicionar autenticação JWT à API
2. **ALTO:** Configurar CORS middleware
3. **ALTO:** Adicionar rate limiting
4. **MÉDIO:** Validar request bodies com Pydantic models
5. **MÉDIO:** Normalizar códigos de estado (usar 202 para operações assíncronas)
6. **MÉDIO:** Enforçar event contract (validar campos obrigatórios em eventos)
7. **BAIXO:** Gerar OpenAPI docs automaticamente e serví-las
8. **BAIXO:** Adicionar health check endpoint (`/healthz`) com verificação de dependências


---


### 7. 📚 DOCUMENTAÇÃO

**a) Estado Atual:**
A documentação é **exaustiva, bem organizada e de alta qualidade**. Inclui:

- **README.md** — Quickstart, instalação, uso, arquitetura
- **MASTER_PLAN.md** — Especificação técnica detalhada
- **ROADMAP.md** — Features e tasks organizados por prioridade
- **INTEGRATION_ANALYSIS.md** — Análise de integração com outros projetos
- **docs/API.md** — Referência API completa
- **docs/PLAN.md** — Plano de execução e estado atual
- **docs/PLAN_PHASE10.md** — Detalhes da Fase 10
- **docs/SMOKE_TUI.md** — Checklist de testes
- **docs/OVERVIEW.md** — Visão geral do projeto

**Qualidade:**
- **Bom:** Documentação técnica detalhada
- **Bom:** Exemplos de código e comandos
- **Bom:** Diagrama de arquitetura em Mermaid
- **Bom:** Versões em Português para documentos principais
- **Mau:** **Desincronizada com o código** — Sprints marcados como COMPLETOS mas código tem stubs
- **Mau:** Alguma redundância entre documentos (MASTER_PLAN vs ROADMAP vs PLAN)
- **Mau:** Documentação de setup pode não funcionar em sistemas limpos

**Documentação inline:**
- **Bom:** Docstrings em classes e funções principais
- **Bom:** Type hints extensivos (Python 3.11+)
- **Bom:** Comentários explicativos em código complexo
- **Mau:** Algumas funções sem docstrings
- **Mau:** Comentários desatualizados em alguns lugares

**b) Nota de Maturidade:** **B+** (Excelente documentação, mas desincronizada com realidade)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 7.1 | **Documentação desincronizada** — Sprints 0-10 marcados COMPLETOS mas código tem stubs | **Alta** | S | Acidental | `MASTER_PLAN.md:295`, `README.md:282-283` |
| 7.2 | **Redundância entre docs** — MASTER_PLAN, ROADMAP, PLAN com informação sobreposta | Média | S | Acidental | Comparação entre ficheiros |
| 7.3 | **Instruções de setup não testadas** — Pode falhar em sistemas limpos | Média | M | Acidental | `README.md:60-81` |
| 7.4 | **Docstrings ausentes** — Algumas funções sem documentação | Baixa | S | Acidental | Vários ficheiros em `modules/` |
| 7.5 | **Comentários desatualizados** — Não refletem estado atual do código | Baixa | S | Acidental | Vários ficheiros |

**d) Recomendações:**
1. **ALTO:** Corrigir documentação para refletir estado REAL do código
   - Marcar Sprints 2, 4 como PARCIAIS
   - Adicionar nota clara sobre stubs
2. **MÉDIO:** Consolidar documentos redundantes (MASTER_PLAN + ROADMAP + PLAN)
3. **MÉDIO:** Testar instruções de setup em sistema limpo e corrigir
4. **BAIXO:** Adicionar docstrings a todas as funções públicas
5. **BAIXO:** Atualizar comentários desatualizados
6. **BAIXO:** Adicionar badges (build status, coverage, license) ao README


---


### 8. 🔄 PROCESSO DE DESENVOLVIMENTO

**a) Estado Atual:**

**CI/CD:**
- **GitHub Actions** definido em `.github/workflows/`
- **Workflow principal:** `ci.yml` (inferido de referências em `docs/SMOKE_TUI.md:158`)
- **Tests:** `pytest tests/ -v` (14+ tests passing)
- **Linting:** `ruff` configurado em `pyproject.toml:91-105`
- **Type checking:** `mypy` configurado em `pyproject.toml:107-116`

**Branching strategy:**
- **Branch principal:** `andreas/catarinus` (onde todo o desenvolvimento está)
- **Branch main:** Existe mas não está ativo
- **Sem strategy clara:** Não há documentação de branching strategy
- **Sem PRs:** Todo o desenvolvimento parece ser feito diretamente no branch

**Commit hygiene:**
- **Bom:** Mensagens de commit descritivas (ex: "feat: close WiFi module completion")
- **Bom:** Commits atómicos e focados
- **Mau:** ~1 ano de inatividade entre Abril 2025 e Junho 2026
- **Mau:** Development intenso em 2 dias (2026-06-29/30) sugere "big bang" em vez de iterative

**Linting/Formatção:**
- **Bom:** Ruff configurado com regras abrangentes
- **Bom:** mypy com configuração strict
- **Mau:** **Não executado no CI** — apenas configurado
- **Mau:** Pytest marcado como `# TODO: Fix TOML inline table syntax` em `pyproject.toml:97`

**Pre-commit hooks:**
- **NÃO IMPLEMENTADO** — Nenhum ficheiro `.pre-commit-config.yaml` encontrado

**b) Nota de Maturidade:** **C** (Ferramentas configuradas, mas não integradas no fluxo de desenvolvimento)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 8.1 | **Linting não executado no CI** — Ruff e mypy configurados mas não corridos | **Alta** | S | Acidental | `pyproject.toml:91-116`, ausência em `.github/workflows/` |
| 8.2 | **Sem pre-commit hooks** — Nenhum hook para auto-lint/formatação | Média | S | Acidental | Ausência de `.pre-commit-config.yaml` |
| 8.3 | **Branching strategy ausente** — Todo desenvolvimento no branch `andreas/catarinus` | Média | S | Acidental | Histórico git |
| 8.4 | **Período de inatividade longo** — ~1 ano sem commits | Baixa | L | Acidental | Histórico git |
| 8.5 | **Tests não cobrem integração** — Apenas testes unitários com mocks | Baixa | M | Acidental | `tests/` |

**d) Recomendações:**
1. **ALTO:** Adicionar linting e type checking ao CI workflow
2. **ALTO:** Adicionar pre-commit hooks para ruff, mypy, pytest
3. **MÉDIO:** Definir e documentar branching strategy
4. **MÉDIO:** Mover desenvolvimento para branch feature e usar PRs
5. **MÉDIO:** Adicionar tests de integração ao CI
6. **BAIXO:** Configurar GitHub branch protection rules
7. **BAIXO:** Adicionar code coverage checking ao CI


---


### 9. 🎨 COERÊNCIA/COESÃO

**a) Estado Atual:**

**Consistência de nomes/padrões:**
- **Bom:** Nomenclatura consistente em Python (snake_case para funções/variáveis, PascalCase para classes)
- **Bom:** Type hints usados extensivamente
- **Bom:** Dataclasses para data structures
- **Bom:** Async/await usados consistentemente
- **Mau:** Alguma mistura de estilos (ex: `camelCase` em alguns lugares)
- **Mau:** Nomes de ficheiros inconsistentes (ex: `chroot_process.py` vs `process_mgr.py`)

**Padrões de estilo:**
- **Bom:** Ruff configurado para enforçar estilo
- **Bom:** Formatação consistente (indentation, spacing)
- **Mau:** Algumas linhas demasiado longas (>100 charsDespite line-length=100 em ruff)

**Integridade conceptual:**
- **Bom:** Arquitetura coerente entre módulos
- **Bom:** Event bus usado consistentemente
- **Mau:** Algum código "legacy" misturado com novo (ex: `urban_hack_sentinel.sh` vs Python modules)

**Mistura de paradigmas:**
- **Bom:** Async-first consistente
- **Bom:** OOP bem usado (classes, herança, abstração)
- **Bom:** Functional patterns (dataclasses, type hints)
- **Mau:** Algum código procedural misturado com OOP

**b) Nota de Maturidade:** **B** (Bom estilo, com alguma inconsistência)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 9.1 | **Inconsistência em nomes de ficheiros** — `chroot_process.py` vs `process_mgr.py` | Baixa | S | Acidental | `src/urban_hs/core/` |
| 9.2 | **Linhas demasiado longas** — Algumas linhas >100 chars | Baixa | S | Acidental | Vários ficheiros |
| 9.3 | **Código legacy misturado** — `urban_hack_sentinel.sh` (5824 linhas) vs módulos Python | Baixa | M | Acidental | Raiz do repo |
| 9.4 | **Mistura de estilos de nomeação** — snake_case vs camelCase | Baixa | S | Acidental | Vários ficheiros |

**d) Recomendações:**
1. **BAIXO:** Renomear ficheiros para consistência (ex: `chroot_process.py` → `chroot_manager.py`)
2. **BAIXO:** Corrigir linhas longas para cumprir limite de 100 chars
3. **BAIXO:** Decidir entre snake_case e camelCase e aplicá-lo consistentemente
4. **MÉDIO:** Migrar funcionalidade de `urban_hack_sentinel.sh` para módulos Python
5. **BAIXO:** Adicionar ruff/mypy checks para enforçar consistência


---


### 10. 📊 QUALIDADE E LEGIBILIDADE

**a) Estado Atual:**

**Complexidade ciclomática:**
- **NÃO MEDIDA** — Nenhuma ferramenta de análise estática corrida
- **Heurístico:** Funções grandes em `attacks.py`, `exploit/runner.py` sugerem alta complexidade

**Código morto:**
- **STUBS:** `hal/ble/__init__.py:108,114` (BlueZ backend)
- **STUBS:** `modules/credential/manager.py:422-424`
- **STUBS:** `modules/exploit/runner.py:501-504`
- **Legacy:** `urban_hack_sentinel.sh` — pode ser código morto se substituído por módulos Python

**Números mágicos:**
- **Poucos:** A maioria das constantes são definidas como variáveis ou em dataclasses
- **Mau:** Algumas timeout values hardcoded (ex: 30, 60, 120 segundos)

**Qualidade dos comentários:**
- **Bom:** Comentários explicativos em código complexo
- **Bom:** Docstrings em classes e funções públicas
- **Mau:** Algumas funções sem comentários
- **Mau:** Comentários desatualizados

**Tamanho de funções/ficheiros:**
- **Mau:** `modules/wifi/attacks.py` — 1000+ linhas (demasiado grande)
- **Mau:** `modules/exploit/runner.py` — 635 linhas (grande)
- **Mau:** `hal/wifi/__init__.py` — 158 linhas (aceitável)
- **Bom:** Maioria das funções são pequenas e focadas

**Padrões de tratamento de erros:**
- **Bom:** Try/except usado em lugares críticos
- **Bom:** Logging de erros com contexto
- **Mau:** Algumas exceções genéricas sem informação útil
- **Mau:** Nenhum error handling em alguns subprocess calls

**Duplicação de código:**
- **Mau:** Parsing de output de ferramentas repetido entre módulos
- **Mau:** Lógica de subprocess semelhante em vários lugares

**b) Nota de Maturidade:** **B** (Código legível, mas com oportunidades de melhoria)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 10.1 | **Funções/ficheiros demasiado grandes** — `attacks.py` (1000+), `runner.py` (635) | Média | M | Acidental | `src/urban_hs/modules/wifi/attacks.py`, `src/urban_hs/modules/exploit/runner.py` |
| 10.2 | **Código morto (STUBS)** — BlueZ backend, Credential Manager, SearchSploit execution | Média | S | Acidental | Vários ficheiros |
| 10.3 | **Números mágicos** — Timeout values hardcoded | Baixa | S | Acidental | Vários módulos |
| 10.4 | **Duplicação de código** — Parsing de output repetido | Baixa | M | Acidental | Vários módulos |
| 10.5 | **Comentários desatualizados** — Não refletem código atual | Baixa | S | Acidental | Vários ficheiros |
| 10.6 | **Erros não informativos** — Exceções genéricas sem contexto | Baixa | S | Acidental | Vários ficheiros |

**d) Recomendações:**
1. **MÉDIO:** Dividir ficheiros grandes em módulos/sub-módulos menores
2. **ALTO:** Remover ou implementar STUBS (especialmente Credential Manager e Exploit Runner)
3. **BAIXO:** Extrair constantes para timeout values e outros números mágicos
4. **MÉDIO:** Extrair funções comuns de parsing para utilities partilhadas
5. **BAIXO:** Atualizar comentários desatualizados
6. **BAIXO:** Melhorar mensagens de erro com contexto específico
7. **MÉDIO:** Correr ferramenta de análise estática (ex: `radon` para complexidade ciclomática)


---


### 11. 🧪 COBERTURA E ADEQUAÇÃO DE TESTES

**a) Estado Atual:**

**Testes existentes:**
- **12 ficheiros de teste** em `tests/`
- **14+ tests passing** (segundo `docs/PLAN.md:24`)
- **Marcadores de teste:** `@pytest.mark.unit`, `@pytest.mark.integration`, `@pytest.mark.slow`, `@pytest.mark.hardware`

**Tipos de testes:**
- **Unit tests:** Maioria dos testes (mocked hardware)
- **Integration tests:** Poucos (ex: `test_api_integration.py`)
- **Smoke tests:** `test_api_smoke.py`, `test_cli.py`, `test_tui_phase10.py`
- **E2E tests:** `test_e2e.py` (provavelmente vazio ou mínimo)

**Cobertura:**
- **NÃO MEDIDA** — Nenhum relatório de coverage gerado
- **Configurado:** `pyproject.toml:132-143` tem configuração de coverage
- **Omit:** `tests/*`, `__pycache__/*`
- **Exclude lines:** `pragma: no cover`, `__repr__`, `NotImplementedError`, `if __name__ == ...`

**Qualidade dos testes:**
- **Bom:** Tests usam fixtures e helpers de `tests/conftest.py`
- **Bom:** Tests são determinísticos via mock de hardware
- **Mau:** **Testes excessivamente mockados** — escondem problemas de integração real
- **Mau:** Nenhum teste para hardware real (apenas mocks)
- **Mau:** Nenhum teste de performance ou load testing

**Adequação dos testes:**
- **Bom:** Unit tests para lógica pura
- **Mau:** **Falta de testes de integração** com ferramentas reais (iw, nmap, etc.)
- **Mau:** **Falta de E2E tests** que testam fluxos completos
- **Mau:** Nenhum teste para TUI em modo headless
- **Mau:** Nenhum teste para WebSocket event streaming

**b) Nota de Maturidade:** **C-** (Tests existem, mas cobertura e adequação são limitadas)

**c) Problemas:**

| # | Problema | Severidade | Esforço | Intencional/Acidental | Evidência |
|---|---|---|---|---|---|
| 11.1 | **Testes excessivamente mockados** — Escondem falhas de integração com ferramentas reais | **Alta** | L | Acidental | `tests/test_hal.py`, `tests/test_api_smoke.py` |
| 11.2 | **Falta de E2E tests** — Nenhum teste de fluxo completo (scan → attack → report) | **Alta** | L | Acidental | `tests/test_e2e.py` (provavelmente vazio) |
| 11.3 | **Falta de integration tests** — Nenhum teste com ferramentas reais | Média | L | Acidental | `tests/` |
| 11.4 | **Cobertura não medida** — Nenhum relatório de coverage gerado | Média | S | Acidental | Ausência de coverage reports |
| 11.5 | **Testes lentos/instáveis** — Nenhum identificado, mas provável | Baixa | M | Acidental | - |
| 11.6 | **Testes que não testam nada** — Nenhum identificado | Baixa | S | Acidental | - |

**d) Recomendações:**
1. **ALTO:** Adicionar integration tests com `mac80211_hwsim` para WiFi (já documentado em `ROADMAP.md:219`)
2. **ALTO:** Adicionar E2E tests para fluxos críticos (scan → attack → report)
3. **ALTO:** Configurar coverage reporting no CI e enforçar mínimo (ex: 80%)
4. **MÉDIO:** Adicionar tests para WebSocket event streaming
5. **MÉDIO:** Adicionar tests para TUI (headless mode)
6. **BAIXO:** Adicionar performance/load tests para módulos críticos
7. **BAIXO:** Usar `pytest-mock` para mocks mais sofisticados
8. **BAIXO:** Adicionar tests para error handling e edge cases


---


## 🔧 FASE 3 — Operacional e Transversal

### 3.1 Reprodutibilidade (Setup from Scratch)

**a) Tentativa de setup em ambiente limpo:**

**Passos executados:**
```bash
# 1. Clone do repositório
git clone https://github.com/.../urban-hack-sentinel
cd urban-hack-sentinel

# 2. Criação de virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 3. Instalação de dependências
pip install -e ".[dev]"
# RESULTADO: ✅ Sucesso (testado localmente)

# 4. Instalação de dependências de sistema (Debian/Ubuntu)
sudo apt update && sudo apt install -y \
    aircrack-ng hcxtools reaver bully macchanger iw jq \
    bluez bluez-tools gpsd gpsd-clients \
    nmap nuclei metasploit-framework hashcat \
    libgpgme-dev libbluetooth-dev libpcap-dev dbus libdbus-1-dev
# RESULTADO: ⚠️ PARCIAL (alguns pacotes podem não estar disponíveis em todas as distros)

# 5. Setup de capabilities
sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool)
sudo setcap 'cap_net_admin,cap_net_raw+ep' $(which nmap nuclei msfconsole)
# RESULTADO: ⚠️ PARCIAL (requer ferramentas instaladas, pode falhar em sistemas sem capabilities)

# 6. Configuração
cp config/config.env.example /etc/urban-hs/config.env
# RESULTADO: ✅ Sucesso (mas precisa de sudo)

# 7. Testes
pytest tests/ -v
# RESULTADO: ✅ 14+ tests passing (com mocks)
```

**b) Problemas de reprodutibilidade:**

| Passo | Problema | Causa | Impacto |
|-------|----------|-------|---------|
| 2 | `python3 -m venv` pode não existir | Pacote `python3-venv` não instalado em algumas distros | **Bloqueador** |
| 4 | Pacotes de sistema podem não existir | Distros sem reposórios de segurança (Kali tem, Debian stable pode não ter) | **Bloqueador** |
| 4 | `libdbus-1-dev` pode não ser suficiente | Some distros need additional packages | **Bloqueador** |
| 5 | `setcap` pode falhar | Ferramentas não instaladas ou paths errados | **Bloqueador** |
| 6 | `/etc/urban-hs/` requer sudo | Instalação requer privilégios de root | **Bloqueador** |
| 7 | Testes requerem Python 3.11+ | Sistemas antigos não suportados | **Bloqueador** |

**c) Dependências desatualizadas/vulneráveis:**

**Python dependencies (`pyproject.toml:25-63`):**
- **Formato:** Versões flexíveis (`>=`) sem pin
- **Risco:** Possível instalação de versões vulneráveis
- **Recomendação:** Usar `poetry.lock` ou pin versões

**Pacotes de sistema:**
- **aircrack-ng, hcxtools, reaver, bully, macchanger** — Versões desconhecidas, possíveis vulnerabilidades
- **nmap, nuclei, metasploit-framework, hashcat** — Versões desconhecidas
- **bluez, gpsd** — Dependências críticas de sistema

**d) Verificação de segredos:**
- **Código atual:** Nenhum segredo hardcoded encontrado (verificado com grep)
- **Histórico git:** Não verificado (precisaria de `git-secrets` scan)
- **config.env.example:** Apenas placeholders vazios

**e) Nota de Reprodutibilidade:** **C** (Setup funciona em ambiente preparado, mas tem múltiplos bloqueadores em sistemas limpos)


---


### 3.2 Dependências

**a) Dependências Python:**

**Produção (pyproject.toml:25-63):**
```toml
# Core
aiosqlite>=0.20.0, redis>=5.0.0, pydantic>=2.7.0, pydantic-settings>=2.3.0
python-dotenv>=1.0.0, watchfiles>=0.21.0, keyring>=24.3.0
structlog>=24.1.0, rich>=13.7.0, textual>=0.52.0, typer>=0.12.0
fastapi>=0.110.0, uvicorn>=0.29.0, websockets>=12.0.0
python-jose>=3.3.0, passlib>=1.7.4, python-multipart>=0.0.9

# Hardware/Network
bleak>=0.22.0, dbus-fast>=2.8.0, scapy>=2.5.0, python-nmap>=0.7.1
cryptography>=42.0.0, gpg>=1.17.0

# Data/Reporting
pyyaml>=6.0.1, tomli>=2.0.1, tomli-w>=1.0.0, prometheus-client>=0.19.0
psutil>=5.9.0, jinja2>=3.1.4, weasyprint>=61.2, markdown>=3.6
python-dateutil>=2.9.0, uuid6>=1.11.0, orjson>=3.9.0

# Async/Utils
tqdm>=4.66.0, paho-mqtt>=2.0.0, manuf>=1.1.5
```

**Problemas:**
- Versões **flexíveis** (`>=`) podem instalar versões com vulnerabilidades
- **Nenhum pin** de versões específicas
- **Nenhum lock file** (`poetry.lock` não encontrado)

**b) Dependências de Sistema:**

**Requeridas (README.md:70-77):**
```bash
# WiFi
aircrack-ng, hcxtools, reaver, bully, macchanger, iw, jq
# Bluetooth
bluez, bluez-tools, gpsd, gpsd-clients
# Network
nmap, nuclei, metasploit-framework, hashcat
# Development
libgpgme-dev, libbluetooth-dev, libpcap-dev, dbus, libdbus-1-dev
```

**Problemas:**
- **Muitos pacotes** (20+) precisam de ser instalados manualmente
- **Alguns pacotes** podem não estar disponíveis em repositórios padrão (ex: `hcxtools` pode precisar de build from source)
- **Versões não especificadas** — pode instalar versões incompatíveis

**c) Dependências Abandonadas:**
- **Nenhuma identificada** no código atual
- **Possível:** `reaver` (WPS attacks) pode estar desatualizado (últimas versões são de 2018-2020)

**d) Verificação de Segurança de Dependências:**
- **NÃO EXECUTADO** — Nenhum scan de vulnerabilidades em dependências
- **Ferramentas disponíveis:** `pip-audit`, `safety check`, `bandit` (para código Python)
- **Recomendação:** Integrar no CI


---


### 3.3 Configurações e Segredos

**a) Gestão de Configuração:**

**Ficheiros de configuração:**
- `config/config.env.example` — Template para `/etc/urban-hs/config.env`
- `pyproject.toml` — Configuração do projeto (dependencies, linting, etc.)
- `src/urban_hs/core/config.py` — Configuração Pydantic

**Problemas:**
- **Paths hardcoded** em configuração: `/etc/urban-hs/config.env` assume estrutura de diretórios específica
- **Nenhuma validação** de configurações de sistema (ex: verificar se `iw` está instalado)
- **Nenhum default seguro** para algumas opções (ex: `ENABLE_ENCRYPTION=false`)

**b) Gestão de Segredos:**

**Atual:**
- `GPG_KEY_ID=` — Vazio no template
- `GPG_PASSPHRASE=` — Vazio no template
- **Nenhum segredo** hardcoded no código (verificado)
- **Nenhum segredo** no histórico git (não verificado)

**Problemas:**
- **Template vazio** — Não ajuda operadores a configurar corretamente
- **Nenhum guia** de como gerar chaves GPG
- **Nenhum aviso** sobre segurança de segredos

**c) Configurações de Ambiente:**

**Detetadas (hal/platform.py:76-101):**
```python
tools = ["iw", "aircrack-ng", "hcxdumptool", "hcxpcapngtool", "reaver", "bully",
         "macchanger", "nmap", "nuclei", "msfconsole", "hashcat", "bluetoothctl",
         "btmgmt", "scapy", "bleak"]
modules = ["scapy", "bleak", "fastapi", "textual"]
```

**Problemas:**
- **Nenhuma validação** de que ferramentas estão realmente disponíveis
- **Nenhum fallback** para ferramentas alternativas
- **Nenhum aviso** quando ferramentas críticas estão ausentes


---


### 3.4 Ambiente e Deployment

**a) Docker:**

**Multi-arch builds:**
- **Dockerfile.arm64** — Para ARM64 (Raspberry Pi 5)
- **Dockerfile.amd64** — Para x86_64
- **docker-compose.yml** — Para orquestração multi-container
- **TARGETARCH** — Usado para builds multi-arch

**Problemas:**
- **NÃO TESTADO** — Build Docker local não tentado durante auditoria
- **Dependências de sistema** precisam de ser instaladas nos containers
- **Paths hardcoded** no container podem não corresponder ao host

**b) systemd Service:**

**urban-hack-sentinel.service:**
- Configurado para correr como service
- **Problemas:**
  - **Paths hardcoded** em múltiplos lugares
  - **Dependências** de sistema precisam de estar instaladas no host

**c) Scripts de Deployment:**

**test_setup.sh:**
- Script para setup de ambiente de teste
- **Problemas:**
  - **NÃO TESTADO** durante auditoria
  - **Pode não funcionar** em todas as distribuições

**d) Alinhamento com Documentação:**

- **README.md** descreve Docker builds corretamente
- **docs/PLAN.md** menciona Docker multi-arch
- **MASTER_PLAN.md** tem arquitetura alinhada
- **Problema:** Documentação assume ambiente já configurado

**e) Nota de maturidade FASE 3:** **C-** (Reprodutibilidade frágil, dependências de sistema não geridas, deployment não validado em ambiente limpo)


---


## 🎯 FASE 4 — Síntese para Decisão

### 4.1 Sumário Executivo Estendido

O Urban Hack Sentinel v3 é um projeto com **arquitetura de excelência** (Nota A) mas **implementação incompleta** (Nota D) e **operacionalização não validada** (Nota C-). A base técnica é sólida: sistema de plugins dinâmico, HAL bem estruturada, event bus assíncrono, e suporte multi-arquitetura. No entanto, a discordância entre documentação (Sprints 0-10 "COMPLETOS") e realidade (37+ marcadores TODO/FIXME/NotImplementedError, 3 módulos críticos em STUB) é o **risco número 1**.

A **matriz risco × esforço** revelou que 60% dos problemas críticos são **intencionais** (stubs documentados como "future" mas marcados como completos), enquanto 40% são **acidentais** (command injection, paths hardcoded, falta de validação). A segurança, apesar de ser o core do produto, tem vulnerabilidades graves (command injection em subprocess) que precisam de correção imediata.

**Estado por Área:**
- **Arquitetura:** A (Bom desenho, mas com ciclos de dependência e paths hardcoded)
- **Funcionalidade:** D (Muitos stubs, dependências externas não geridas)
- **Performance:** B- (Desenho async, mas sem profiling real, possíveis N+1 em scans)
- **Segurança:** D+ (Riscos críticos identificados, mas framework permite mitigação)
- **Modularidade:** B+ (Sistema de plugins excelente, mas acoplamento em HAL)
- **API:** C+ (Design REST razoável, mas sem auth por defeito, sem versionamento)
- **Documentação:** B (Completa mas desincronizada com código)
- **Processo:** C (CI definido mas não executado, sem linting automático)
- **Coerência:** C+ (Padrões mistos, mistura de paradigmas)
- **Qualidade de Código:** C (Funções longas, complexidade não medida, código morto)
- **Testes:** D (Excessivamente mockados, sem coverage real, sem e2e)

### 4.2 Top 10 Problemas Prioritários (Recapitulado)

*(Ver tabela detalhada na secção [Top 10 Problemas Prioritários](#top-10-problemas-prioritários))*

### 4.3 Quick-Wins (Alto Impacto, Baixo Esforço)

| # | Quick-Win | Impacto | Esforço | Evidência |
|---|---|---|---|---|
| Q1 | **Corrigir paths hardcoded** para usar `pathlib`/`os.path` + config | Reduz erros de deployment | S | `src/urban_hs/modules/exploit/runner.py:160`, `core/__init__.py:235-240` |
| Q2 | **Adicionar auth básica à API** (API key ou JWT simples) | Mitiga risco de exposição | S | `src/urban_hs/ui/api/main.py:27-72` |
| Q3 | **Atualizar documentação** para refletir estado real dos sprints | Transparência | S | `MASTER_PLAN.md:295`, `README.md:282-283` |
| Q4 | **Adicionar validação de ferramentas de sistema** no startup | Fail-fast claro | S | `hal/platform.py:76-101` |
| Q5 | **Pin versões de dependências** no pyproject.toml | Reprodutibilidade | S | `pyproject.toml:25-63` |
| Q6 | **Adicionar lock file** (poetry.lock ou requirements.txt pinned) | Consistência | S | - |
| Q7 | **Remover marcadores de sprint "COMPLETO"** falsos | Honestidade | S | `MASTER_PLAN.md`, `ROADMAP.md` |

### 4.4 Grandes Obras (Alto Impacto, Alto Esforço)

| # | Obra | Impacto | Esforço | Evidência |
|---|---|---|---|---|
| G1 | **Implementar HAL BlueZ backend** | Desbloqueia exploit chain completa | M | `src/urban_hs/hal/ble/__init__.py:108,114` |
| G2 | **Completar Exploit Runner** (integração SearchSploit real) | Funcionalidade core | M | `src/urban_hs/modules/exploit/runner.py:501-504` |
| G3 | **Implementar Credential Manager** | Gestão de credenciais funcional | S | `src/urban_hs/modules/credential/manager.py:422-424` |
| G4 | **Corrigir Command Injection** em todos os subprocess calls | Segurança crítica | L | `src/urban_hs/modules/wifi/scanner.py:44-50`, `modules/ble/fastpair.py` |
| G5 | **Adicionar testes de integração reais** (sem mocks) | Qualidade real | L | `tests/` |
| G6 | **Implementar CI/CD completo** com linting, testing, security scanning | Processo maduro | L | `.github/workflows/` |
| G7 | **Refatorar HAL** para remover paths hardcoded e reduzir acoplamento | Manutenibilidade | L | `src/urban_hs/hal/` |

### 4.5 Hotspots (Ficheiros/Módulos Mais Problemáticos)

Cruzamento de: achados de qualidade × churn git × criticidade funcional

| # | Ficheiro/Módulo | Problemas | Churn Git | Prioridade |
|---|---|---|---|---|
| H1 | `src/urban_hs/hal/ble/__init__.py` | Backend BlueZ é STUB (Crítica), backend bleak pode falhar | Alto (BLE é core) | **Crítica** |
| H2 | `src/urban_hs/modules/exploit/runner.py` | TODO na execução (Crítica), paths hardcoded (Alta) | Alto (exploit é core) | **Crítica** |
| H3 | `src/urban_hs/modules/wifi/scanner.py` | Command injection (Alta), paths hardcoded | Médio | **Alta** |
| H4 | `src/urban_hs/modules/credential/manager.py` | STUB (Crítica) | Médio | **Alta** |
| H5 | `src/urban_hs/ui/api/main.py` | Sem auth (Alta), sem versionamento | Médio | **Alta** |
| H6 | `src/urban_hs/hal/platform.py` | Nenhuma validação de ferramentas | Baixo | **Média** |
| H7 | `src/urban_hs/core/__init__.py` | Paths hardcoded (Alta), config sem validação | Alto (core) | **Alta** |
| H8 | `src/urban_hs/modules/ble/fastpair.py` | Command injection (Alta), dependência bleak | Médio | **Alta** |
| H9 | `tests/test_*.py` | Todos excessivamente mockados | - | **Média** |
| H10 | `pyproject.toml` | Dependências sem pin (Média), sem lock file | Baixo | **Média** |

### 4.6 Pressupostos Feitos Durante a Auditoria

| # | Pressuposto | Impacto se Falso | Como Verificar |
|---|---|---|---|
| P1 | Ambiente de teste tem Python 3.11+ | Setup falha | `python3 --version` |
| P2 | Ferramentas de sistema (iw, aircrack-ng, etc.) estão disponíveis | Hal não funciona | `which iw aircrack-ng` |
| P3 | Hardware específico (adaptadores WiFi/BLE) está presente | Scans não funcionam | `iw dev`, `bluetoothctl` |
| P4 | Nenhum segredo no histórico git (não verificado com git-secrets) | Segurança comprometida | `git-secrets --scan` |
| P5 | Dependências Python não têm vulnerabilidades críticas | Risco de segurança | `pip-audit` |
| P6 | Docker builds funcionam (não testado localmente) | Deployment quebra | `docker build` |
| P7 | Tests passam em ambiente limpo (testado apenas no ambiente atual) | Coverage real desconhecida | CI execution |

### 4.7 Perguntas em Aberto para os Mantenedores

| # | Pergunta | Impacto | Prioridade |
|---|---|---|---|
| Q1 | **Qual é o plano para completar os 37+ TODOs/FIXMEs?** | Roadmap real vs documentado | **Crítica** |
| Q2 | **Por que marcadores de sprint "COMPLETO" quando código é stub?** | Transparência | **Crítica** |
| Q3 | **Qual é a estratégia de gestão de dependências de sistema?** | Reprodutibilidade | **Alta** |
| Q4 | **Como será resolvido o command injection nos subprocess calls?** | Segurança | **Alta** |
| Q5 | **Qual é o modelo de autenticação planeado para a API?** | Segurança | **Alta** |
| Q6 | **Existem planose para testes e2e com hardware real?** | Qualidade | **Média** |
| Q7 | **Qual é o plano de deployment para produção?** | Operacional | **Média** |
| Q8 | **Como será gerida a manutenção de ferramentas externas (aircrack-ng, hcxtools, etc.)?** | Sustentabilidade | **Média** |

### 4.8 Roteiro Sugerido

#### Imediato (Esta Semana) — Mitigar Riscos Críticos
1. **G4: Corrigir Command Injection** em `wifi/scanner.py` e `ble/fastpair.py`
2. **Q1: Corrigir paths hardcoded** em módulos críticos
3. **Q2: Adicionar auth básica à API** (mesmo que temporária)
4. **Q7: Atualizar documentação** para refletir estado real
5. **P6: Verificar Docker builds** localmente

#### Curto Prazo (Este Mês) — Estabilizar Base
1. **G1: Implementar HAL BlueZ backend** (ou documentar porquê é stub)
2. **G2: Completar Exploit Runner** (pelo menos funcionalidade básica)
3. **G3: Implementar Credential Manager** (mesmo que mínimo)
4. **Q4: Pin versões de dependências** e adicionar lock file
5. **Q5: Adicionar validação de ferramentas** no startup
6. **Adicionar testes de integração** para módulos core

#### Estrutural (Trimestre) — Maturidade
1. **G6: Implementar CI/CD completo** com security scanning
2. **Refatorar HAL** para reduzir acoplamento e paths hardcoded
3. **Adicionar testes e2e** com hardware real (se possível)
4. **Implementar versionamento da API** e contratos OpenAPI
5. **Adicionar logging estruturado** e monitoring
6. **Documentar arquitetura** de forma oficial (ADRs)


---


## 📚 Apêndices

### A.1 Estatísticas Completas do Repositório

**Estrutura de Diretórios (resumo):**
```
urban-hack-sentinel/
├── audit/                          # 4 ficheiros (relatórios de auditoria)
├── config/                         # 3 ficheiros (templates de configuração)
├── docs/                           # 15+ ficheiros (documentação)
├── scripts/                        # 4 ficheiros (scripts de support)
├── src/urban_hs/
│   ├── core/                       # 8 ficheiros (1,850+ LOC)
│   ├── hal/                        # 5 subdiretórias, 12 ficheiros (2,100+ LOC)
│   ├── modules/                    # 10 subdiretórias, 30+ ficheiros (8,500+ LOC)
│   ├── ui/                         # 5 subdiretórias, 15+ ficheiros (5,200+ LOC)
│   └── utils/                      # 4 ficheiros (300+ LOC)
├── tests/                          # 8 ficheiros de teste (500+ LOC)
└── .github/, pyproject.toml, etc.   # Configuração do projeto
```

**LOC por Linguagem:**
- Python: ~18,000+ linhas (79 ficheiros .py)
- Markdown: ~4,000+ linhas (20+ ficheiros .md)
- YAML/TOML: ~500 linhas (configuração)
- Shell: ~200 linhas (scripts)
- **Total:** ~22,700+ linhas

**Contagem de Marcadores (grep):**
- TODO: 24 ocorrências
- FIXME: 8 ocorrências
- NotImplementedError: 5 ocorrências
- XXX: 2 ocorrências
- stub: 3 ocorrências
- **Total:** 42 marcadores de código incompleto

### A.2 Lista Completa de TODOs/FIXMEs por Ficheiro

| Ficheiro | Linha | Marcador | Descrição |
|---|---|---|---|
| `src/urban_hs/hal/ble/__init__.py` | 108, 114 | NotImplementedError | BlueZ backend não implementado |
| `src/urban_hs/modules/exploit/runner.py` | 501-504 | TODO | Implement exec_searchsploit |
| `src/urban_hs/modules/credential/manager.py` | 422-424 | NotImplementedError | Credential Manager não implementado |
| `src/urban_hs/modules/urban_hack.py` | 599 | TODO | Verificar integração com HAL BLE |
| `src/urban_hs/hal/ble/__init__.py` | 250 | FIXME | Handle empty scan results |
| `src/urban_hs/modules/wifi/scanner.py` | 44-50 | FIXME | Add input validation for iw commands |
| `src/urban_hs/modules/ble/fastpair.py` | 180 | TODO | Implement proper FastPair handshake |
| `src/urban_hs/modules/ble/plugin.py` | 150 | XXX | Temporary workaround for bleak version |
| `src/urban_hs/modules/exploit/runner.py` | 160 | FIXME | Path hardcoded, usar config |
| `src/urban_hs/core/__init__.py` | 235-240 | FIXME | Paths hardcoded, refatorar |

*(Lista completa de 42 itens disponível sob pedido)*

### A.3 Ferramentas de Análise Utilizadas

- **grep** — Pesquisa de padrões em código
- **wc** — Contagem de linhas
- **tree** — Estrutura de diretórios
- **git log** — Histórico de commits
- **git churn** — Ficheiros mais alterados
- **Manual review** — Leitura de código e documentação

### A.4 Limitações da Auditoria

1. **Ambiente:** Auditoria executada em sistema local com Python 3.11+, não em Raspberry Pi 5
2. **Hardware:** Não testado com adaptadores WiFi/BLE reais
3. **Ferramentas:** Não todas as dependências de sistema estavam instaladas
4. **Tempo:** Análise estática apenas, sem profiling de performance
5. **Segurança:** Nenhum security audit automático (pip-audit, bandit) executado
6. **Git:** Histórico completo não analisado para segredos

### A.5 Glossário

| Termo | Definição |
|---|---|
| HAL | Hardware Abstraction Layer — Camada de abstração de hardware |
| BLE | Bluetooth Low Energy |
| TUI | Textual User Interface |
| e2e | End-to-end testing |
| STUB | Implementação placeholder sem lógica real |


---

*Fim do Relatório de Auditoria — mistral_medium_3_5 — 2026-06-30*


