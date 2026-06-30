# Audit #3 — urban-hack-sentinel
## Auditor: mimo_v2_5_free
## Date: 2026-06-30
## Scope: Full repository analysis (HEAD = 579546a)

---

# FASE 0 — Reconhecimento

## 0.1 Visão geral do projeto

**Urban Hack Sentinel v3** é uma plataforma modular de auditoria wireless/Bluetooth/IoT/Network escrita em Python 3.11+, concebida para Raspberry Pi (ARM64) e x86/64. Combina um framework Python assíncrono com uma camada de abstração de hardware (HAL) que encapsula ferramentas de sistema (aircrack-ng, nmap, reaver, etc.) e fornece três interfaces: CLI (Typer), TUI (Textual) e Web (FastAPI + HTMX).

**Público-alvo:** Auditors de segurança, estudantes, investigadores em cibersegurança — operação em redes próprias (disclaimer legal proeminente).

**Deployment:** Raspberry Pi 5 ou máquina x86, execução via systemd ou Docker multi-arch.

## 0.2 Estatísticas do repositório

| Métrica | Valor |
|---------|-------|
| Primeiro commit | 2025-04-22 |
| Último commit | 2026-06-30 |
| Total commits | 46 |
| Autores | 3 (Andreas_Catarinus: 56, Claude: 7, Santolass06: 2) |
| Linguagem | Python 3.11+ |
| LOC total (src/) | ~24.570 |
| Ficheiros .py | ~55 |
| Frameworks | FastAPI, Textual, Typer, Pydantic v2, aiosqlite, bleak, scapy, structlog |
| Testes | 11 ficheiros, ~86 funções de teste, ~1.907 LOC |
| CI/CD | GitHub Actions (ci.yml: pytest; release.yml: Docker multi-arch + SBOM + cosign) |

## 0.3 Marcadores TODO/FIXME/HACK

| Marcador | Localização | Conteúdo |
|----------|-------------|----------|
| TODO | `src/urban_hs/modules/urban_hack.py:599` | `# TODO: Full exploit chain` |
| TODO | `src/urban_hs/modules/ble/plugin.py:250` | `# TODO: Implement full exploit chain` |
| TODO | `src/urban_hs/modules/exploit/runner.py:501` | `# TODO: Implement actual exploit execution` |
| TODO | `src/urban_hs/modules/wifi/fragattacks.py:290` | `# TODO: parse from output` (affected_frames hardcoded a 0) |
| NotImplementedError | `src/urban_hs/modules/credential/manager.py:422-424` | raise NotImplementedError |
| NotImplementedError | `src/urban_hs/hal/ble/__init__.py:108,114` | BlueZ D-Bus backend stub |
| NotImplemented | `src/urban_hs/cli/main.py:94` | Windows compat catch |

## 0.4 Histórico Git como sinal

- **Idade:** ~14 meses (Abril 2025 – Junho 2026)
- **Frequência:** bursts de atividade — sprint commits em massa, seguidos de pausas longas
- **Ficheiros com maior churn (estimado):** `src/urban_hs/modules/wifi/scanner.py` (4 commits), `src/urban_hs/ui/api/main.py` (6 commits), `src/urban_hs/modules/ble/exploit_chain.py` (6 commits)
- **Padrão:** Squash/merge de sprints inteiros — mensagens de commit são descritivas e organizadas

## 0.5 Contradições entre documentação e código

| Afirmação nos docs | Realidade no código | Severidade |
|---------------------|---------------------|------------|
| README: "Phases 0–10 completed" | Código mostra módulos com TODOs, stubs e NotImplementedError (exploit runner, credential manager, BLE D-Bus) | Média |
| MASTER_PLAN: "Redis (cache+pub)" | Config declara Redis mas storage.py não tem integração Redis funcional — só aiosqlite | Média |
| README: "React PWA Frontend" | Frontend é HTMX + Alpine.js, não React (src/urban_hs/ui/web/ não existe como diretório com código React) | Baixa |
| MASTER_PLAN: "Alembic-style migrations" | storage.py tem schema inline, sem sistema de migrations | Baixa |
| README: "JWT auth, RBAC" | API não tem autenticação implementada — endpoints são abertos | Alta |
| docs/API.md: documenta auth Bearer | Nenhum middleware de auth no FastAPI app | Alta |
| ROADMAP: "Bash para core loop" | Core é 100% Python — bash script (urban_hack_sentinel.sh) é legado/paralelo | Baixa |

## 0.6 O que o projeto pretende ser

Plataforma unificada de pentesting wireless/Bluetooth/IoT para operação contínua em Raspberry Pi, com:
- Scanner WiFi passivo/ativo com múltiplos backends (iw/scapy)
- Ataques WPA2/WPA3 (PMKID, handshake, WPS Pixie Dust, PIN brute)
- BLE Fast Pair (CVE-2025-36911 WhisperPair) e HFP audio capture
- Descoberta de câmaras (mDNS, ONVIF, RTSP)
- Integração Metasploit (RPC + Console)
- HID injection (DuckyScript + USB gadget)
- Reporting com GPG evidence chain
- Dashboard Web/TUI/CLI

---

# FASE 1 — Inventário Intenção → Realidade

| Funcionalidade | Fonte (markdown) | Estado | Evidência | Intencional/Acidental | Notas |
|---|---|---|---|---|---|
| Core Event Bus | MASTER_PLAN S0.2 | IMPLEMENTADO | `core/event_bus.py:1-262` | — | Completo, com DLQ e prioridades |
| Core Config (Pydantic) | MASTER_PLAN S0.4 | IMPLEMENTADO | `core/config.py:1-267` | — | YAML/ENV/hot-reload |
| Core Storage (SQLite) | MASTER_PLAN S0.5 | PARCIAL | `core/storage.py:1-949` | Acidental | Redis declarado mas não integrado |
| Core Process Manager | MASTER_PLAN S0.3 | IMPLEMENTADO | `core/process_mgr.py:1-594` | — | Robust subprocess com streaming |
| Core Logger | MASTER_PLAN S0.6 | IMPLEMENTADO | `core/logger.py` | — | structlog + JSONL |
| Core Health + Prometheus | MASTER_PLAN S0.7 | IMPLEMENTADO | `core/health.py` | — | /healthz, /metrics |
| Plugin System | MASTER_PLAN S0.8 | IMPLEMENTADO | `core/plugins.py:1-673` | — | Dynamic load, metadata |
| Scheduler | MASTER_PLAN (não listado explicitamente) | IMPLEMENTADO | `core/scheduler.py:1-644` | — | Cron + interval triggers |
| Security Hardening | MASTER_PLAN S6.4 | IMPLEMENTADO | `core/security.py:1-610` | — | Seccomp, capabilities, rootless chroot |
| Concurrency | MASTER_PLAN S6.1 | IMPLEMENTADO | `core/concurrency.py` | — | Resource pools |
| Memory Profiler | MASTER_PLAN S6.2 | IMPLEMENTADO | `core/memory.py` | — | Streaming parsers, leak detection |
| WiFi Scanner | MASTER_PLAN S1.1 | IMPLEMENTADO | `modules/wifi/scanner.py:1-508` | — | iw JSON + airodump CSV + scapy |
| Handshake Attack | MASTER_PLAN S1.2 | IMPLEMENTADO | `modules/wifi/attacks.py:1-940` | — | aireplay + airodump |
| PMKID Attack | MASTER_PLAN S1.2 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | hcxdumptool |
| WPS Pixie Dust | MASTER_PLAN S1.3 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | reaver integration |
| WPS PINs | MASTER_PLAN S1.4 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | Common PINs DB |
| Deauth Attack | MASTER_PLAN S1.5 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | Targeted + broadcast |
| Handshake Manager | MASTER_PLAN S1.5 | IMPLEMENTADO | `modules/wifi/__init__.py` | — | Dedup, hashcat, export |
| MAC Changer | MASTER_PLAN S1.6 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | OUI profiles |
| GeoMapper | MASTER_PLAN S1.7 | IMPLEMENTADO | `modules/wifi/geomapper.py` | — | gpsd + WiGLE/KML export |
| FragAttacks | MASTER_PLAN S4.11 | IMPLEMENTADO | `modules/wifi/fragattacks.py` | — | Wrapper vanhoefm |
| Kr00k | MASTER_PLAN S4.10 | IMPLEMENTADO | `modules/wifi/attacks.py` | — | CVE-2019-15126 |
| BLE FastPair Scanner | MASTER_PLAN S2.1 | IMPLEMENTADO | `modules/ble/fastpair.py` | — | Bleak 0xFE2C |
| WhisperPair Tester | MASTER_PLAN S2.2 | IMPLEMENTADO | `modules/ble/__init__.py` | — | GATT connect + KBP |
| WhisperPair Exploit | MASTER_PLAN S2.3 | PARCIAL | `modules/ble/exploit_chain.py:1-641` | Intencional | Estrutura criada, requer HW real |
| BLE D-Bus Backend | MASTER_PLAN S2.4 | STUB | `hal/ble/__init__.py:108-114` | Intencional | NotImplementedError, aguarda BlueZ |
| HFP Audio Capture | MASTER_PLAN S2.6 | PARCIAL | `modules/ble/audio_hfp.py` | Intencional | Estrutura, requer HW real |
| Network Scanner (Nmap) | MASTER_PLAN S3.1 | IMPLEMENTADO | `modules/network/__init__.py:1-1108` | — | Async nmap wrapper |
| Nuclei Runner | MASTER_PLAN S3.2 | IMPLEMENTADO | `modules/network/__init__.py` | — | Template execution |
| Camera Discovery | MASTER_PLAN S3.5 | IMPLEMENTADO | `modules/camera/enumeration.py:1-732` | — | mDNS+UPnP+ONVIF+RTSP |
| Camera Enumeration | MASTER_PLAN S3.6 | PARCIAL | `modules/camera/enumeration.py` | Intencional | Estrutura criada, default creds |
| Camera Vuln Check | MASTER_PLAN S3.7 | PARCIAL | `modules/camera/` | Intencional | Estrutura |
| Metasploit RPC | MASTER_PLAN S4.3 | IMPLEMENTADO | `modules/metasploit/rpc.py:1-635` | — | msgrpc client |
| Metasploit Console | MASTER_PLAN S4.4 | IMPLEMENTADO | `modules/metasploit/console.py` | — | msfconsole wrapper |
| Exploit Runner | MASTER_PLAN S4.5 | STUB | `modules/exploit/runner.py:501` | Acidental | TODO: "Implement actual exploit execution" |
| Credential Manager | MASTER_PLAN S4.6 | PARCIAL | `modules/credential/manager.py:1-740` | Acidental | NotImplementedError em validate |
| Report Generator | MASTER_PLAN S4.7 | IMPLEMENTADO | `modules/reporting/generator.py:1-918` | — | Jinja2 → PDF/HTML/MD |
| GPG Evidence | MASTER_PLAN S4.8 | IMPLEMENTADO | `modules/reporting/gpg_evidence.py:1-701` | — | Sign + audit trail |
| DuckyScript Parser | MASTER_PLAN S5.1 | IMPLEMENTADO | `modules/hid/ducky.py:1-668` | — | Hak5 v1/v3, 7 layouts |
| HID Injector | MASTER_PLAN S5.2 | IMPLEMENTADO | `modules/hid/injector.py` | — | uinput + usb-gadget |
| USB Gadget Manager | MASTER_PLAN S5.3 | IMPLEMENTADO | `modules/hid/gadget.py:1-629` | — | configfs profiles |
| MQTT Attack Suite | MASTER_PLAN S4.15 | IMPLEMENTADO | `modules/mqtt.py:1-738` | — | Broker discovery + brute |
| ESP32 Fingerprinting | MASTER_PLAN S4.18 | IMPLEMENTADO | `modules/esp32.py:1-788` | — | CVE-2025-27840 |
| SSID Confusion | MASTER_PLAN S4.17 | IMPLEMENTADO | `modules/ssid_confusion.py` | — | CVE-2023-52424 |
| BT HID Injection | MASTER_PLAN S4.9 | IMPLEMENTADO | `modules/bt_hid.py:1-724` | — | CVE-2023-45866/21306 |
| FastAPI Backend | MASTER_PLAN S5.4 | PARCIAL | `ui/api/main.py:1-75` | Acidental | REST funciona, mas sem auth/RBAC |
| React PWA Frontend | MASTER_PLAN S5.5 | EM FALA | — | Acidental | README menciona React, código tem HTMX |
| Textual TUI | MASTER_PLAN S5.6 | IMPLEMENTADO | `ui/tui/app.py:1-351` | — | Dashboard + attack UI |
| Rich CLI | MASTER_PLAN S5.7 | IMPLEMENTADO | `cli/main.py:1-153` | — | info, run, modules |
| Alpine Chroot | MASTER_PLAN S4.1 | PARCIAL | `core/chroot_process.py`, `scripts/bootstrap_chroot.sh` | Intencional | Script existe, precisa validação |
| CI/CD | MASTER_PLAN S0.9 | IMPLEMENTADO | `.github/workflows/ci.yml:1-26` | — | pytest on push |
| Docker Multi-arch | MASTER_PLAN (implícito) | IMPLEMENTADO | `docker/Dockerfile.arm64:1-147` | — | amd64 + arm64 |

---

# FASE 2 — Auditoria por Categoria

## 2.1 ARQUITETURA

**Estado:** Geralmente sólida. Camada core bem desacoplada via event bus. Plugin system funcional. HAL existe mas subutilizado.

**Maturidade:** B

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| A1 | Alta | L | **Sem separação entre core e módulos de ataque.** WiFi attacks hardcoded com output_dir `/var/lib/urban-hs/...` sem usar Config | Acidental | `modules/wifi/attacks.py:89,179,309,428,537,638,745` |
| A2 | Média | M | **Ciclo de dependência runtime implícito:** storage → config → event_bus → storage. Funciona via singletons mas dificita testing | Acidental | `core/__init__.py:28-31` |
| A3 | Média | S | **Redis declarado em pyproject.toml e config mas não integrado** — storage.py só usa aiosqlite | Acidental | `pyproject.toml:27`, `core/storage.py` |
| A4 | Baixa | S | **Tres Dockerfiles** (Dockerfile, Dockerfile.arm64, Dockerfile.amd64) — confuso, só Dockerfile.arm64 é canónico | Acidental | `docker/` |
| A5 | Baixa | S | **bash script (urban_hack_sentinel.sh) paralelo** — 584 linhas de bash que duplica funcionalidade Python | Acidental | `urban_hack_sentinel.sh:1-584` |

### Recomendações
1. Extrair paths para Config em vez de hardcoded — crítico para testabilidade
2. Avaliar remoção do bash script legado ou将其 para archival
3. Consolidar Dockerfiles num multi-stage com build args

---

## 2.2 FUNCIONALIDADE

**Estado:** A maioria dos módulos está implementada com lógica real. Exceções: exploit runner (stub), credential validation (NotImplementedError), BLE D-Bus backend (stub).

**Maturidade:** B-

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| F1 | Alta | L | **Exploit Runner é stub** — `execute_exploit()` faz TODO e retorna mock | Acidental | `modules/exploit/runner.py:501` |
| F2 | Alta | M | **Credential validate_credential() raise NotImplementedError** | Acidental | `modules/credential/manager.py:422-424` |
| F3 | Média | S | **BLE D-Bus backend não funciona** — `dbus.Interface` é NoneType | Acidental | `hal/ble/__init__.py:108-114` |
| F4 | Média | S | **FragAttacks affected_frames hardcoded a 0** — TODO: parse from output | Acidental | `modules/wifi/fragattacks.py:290` |
| F5 | Baixa | S | **FastAPI usa `on_event` deprecated** — deveria usar lifespan | Acidental | `ui/api/main.py:37-41` |
| F6 | Baixa | S | **Health check endpoint /healthz retorna 404** no teste (router prefix mismatch?) | Acidental | Teste: `test_api_smoke.py:18` |

### Recomendações
1. Implementar ou remover explícitamente exploit runner
2. Resolver BLE D-Bus: mock para CI, real para hardware
3. Migrar FastAPI para lifespan pattern

---

## 2.3 PERFORMANCE

**Estado:** Não foi possível fazer profiling (sem venv funcional completo). Análise heurística.

**Maturidade:** B (heurístico)

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| P1 | Média | M | **Paths hardcoded causam PermissionError em tests** — módulos tentam criar `/var/lib/urban-hs` no init | Acidental | `modules/wifi/attacks.py:94`, erros de teste |
| P2 | Média | S | **AirodumpScanBackend cria subprocess no `__init__`** — viola lazy init | Acidental | `modules/wifi/scanner.py:381` |
| P3 | Baixa | S | **Storage WAL mode não é explicitamente configurado** — depende de default aiosqlite | Acidental | `core/storage.py` |
| P4 | Baixa | S | **Sem connection pooling explícito para SQLite** — aiosqlite lida com isso internamente mas não há métricas | Acidental | `core/storage.py` |

### Recomendações
1. Aceitar output_dir como parâmetro (ou usar tmp_path em tests) — prioridade alta
2. Lazy-init backends de scan
3. Adicionar PRAGMA optimize ao shutdown do storage

---

## 2.4 SEGURANÇA

**Dado o nome "sentinel", segurança é core do produto. Esta categoria é tratada com rigor extra.**

**Estado:** Misto. Core security.py é robusto (seccomp, capabilities), mas a API não tem autenticação e há vários defaults inseguros.

**Maturidade:** C+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| S1 | **Crítica** | M | **API sem autenticação** — todos os endpoints REST e WebSocket são abertos. Qualquer pessoa na rede pode executar ataques | Acidental | `ui/api/main.py:27-75` (nenhum middleware auth) |
| S2 | **Crítica** | S | **jwt_secret com fallback para `secrets.token_urlsafe(32)`** — gera secret diferente a cada startup, sessões JWT perdidas | Acidental | `core/config.py:150-157` |
| S3 | Alta | S | **Metasploit RPC password default vazia** — `rpc_pass: str = ""` mas validator força raise se vazio | Acidental | `core/config.py:73`, `modules/metasploit/rpc.py:115-116` |
| S4 | Alta | S | **Hardcoded paths sem validação de permissões** — módulos criam diretórios em `/var/lib/urban-hs` sem verificar se o user tem permissão | Acidental | `core/__init__.py:235-239`, `modules/wifi/attacks.py:94` |
| S5 | Alta | M | **Comandos de subprocess passados via string** — risco de command injection se input não for sanitizado | Acidental | `core/process_mgr.py` usa `shlex.split` mas módulos passam strings |
| S6 | Média | S | **Nenhum rate limiting na API** — execução de ataques sem throttling | Acidental | `ui/api/main.py` — nenhum rate limiter |
| S7 | Média | S | **Device quirks JSON (/etc/urban-hs/) sem validação de integridade** — arquivo pode ser modificado por atacante | Acidental | `modules/ble/fastpair.py:546` |
| S8 | Média | S | **WiFi config: `enable_active_attacks: bool = False`** — bom default, mas `legal_warning_shown: bool = False` não impede execução | Intencional | `core/config.py:34-35` |
| S9 | Baixa | S | **Nenhum CORS configurado na FastAPI** — default permite cross-origin | Acidental | `ui/api/main.py` |
| S10 | Baixa | S | **sysctl/log sensitive data** — structlog pode logar payload de eventos com dados sensíveis | Acidental | `core/event_bus.py:38-42` |

### Recomendações
1. **URGENTE:** Implementar auth middleware (Bearer token mínimo) antes de qualquer exposição de rede
2. Gerar jwt_secret no primeiro boot e persistir em ficheiro com permissões 0600
3. Adicionar rate limiting (slowapi ou similar)
4. Configurar CORS explicitamente
5. Auditar todos os pontos de entrada de subprocess para validação de input

---

## 2.5 MODULARIDADE

**Estado:** Boa. Plugin system bem desenhado. Cada módulo é auto-contido. HAL existe mas subutilizado.

**Maturidade:** B+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| M1 | Média | M | **WiFi attacks.py é monolítico** (940 linhas) — HandshakeAttack, PMKIDAttack, WPSPixie, WPSPin, DeauthAttack, Kr00k num único ficheiro | Acidental | `modules/wifi/attacks.py` |
| M2 | Média | S | **Network __init__.py é monolítico** (1108 linhas) — NmapScanner, NucleiRunner, SearchSploitRouter, RouterScan num único ficheiro | Acidental | `modules/network/__init__.py` |
| M3 | Baixa | S | **HAL WiFi subutilizado** — módulos importam process_mgr diretamente em vez de usar HAL | Acidental | `modules/wifi/attacks.py` |
| M4 | Baixa | S | **Exemplo plugins (example_sniffer, example_reporter)** registados no _MODULE_REGISTRY como módulos de produção | Acidental | `modules/__init__.py:41-42` |

### Recomendações
1. Dividir `attacks.py` em ficheiros por tipo de ataque
2. Dividir `network/__init__.py` em módulos separados
3. Remover example plugins do registry de produção

---

## 2.6 API

**Estado:** Estrutura REST funcional com routers bem organizados. Falta autenticação, validação de schema, documentação OpenAPI automática (FastAPI gera mas não está optimizada).

**Maturidade:** C+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| API1 | Alta | M | **Sem autenticação/autorização** — qualquer um executa ataques | Acidental | `ui/api/main.py` |
| API2 | Média | S | **Endpoint /healthz retorna 404** — router prefix mismatch (testes falham) | Acidental | `test_api_smoke.py:18` |
| API3 | Média | S | **Nenhum schema de validação de request body** — endpoints POST aceitam qualquer payload | Acidental | `ui/api/routers/attacks.py` |
| API4 | Média | S | **Sem versionamento de API** — /api/v1/ hardcoded, sem mecanismo de deprecação | Acidental | `ui/api/main.py:46-61` |
| API5 | Baixa | S | **on_event deprecated** — FastAPI recomenda lifespan | Acidental | `ui/api/main.py:37-41` |

### Recomendações
1. Implementar auth middleware antes de exposição
2. Adicionar Pydantic models para request/response validation
3. Usar lifespan pattern em vez de on_event

---

## 2.7 DOCUMENTAÇÃO

**Estado:** Boa. Bilingue (EN/PT). API docs detalhadas. Arquitetura documentada. Mas há contradições (ver Fase 0.5).

**Maturidade:** B+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| D1 | Média | S | **README menciona "React PWA"** mas código é HTMX + Alpine.js | Acidental | `README.md:206` |
| D2 | Média | S | **docs/API.md documenta auth Bearer** mas não existe no código | Acidental | `docs/API.md` |
| D3 | Baixa | S | **MASTER_PLAN.md e ROADMAP.md na raiz são legacy** — já archived em docs/archive/ mas permanecem na raiz | Intencional | `MASTER_PLAN.md`, `ROADMAP.md` |
| D4 | Baixa | S | **config.env.example duplicado** (raiz + config/) | Acidental | `config.env.example`, `config/config.env.example` |

### Recomendações
1. Atualizar README para refletir HTMX reality
2. Remover ou marcar claramente docs legacy
3. Consolidar config.env.example

---

## 2.8 PROCESSO DE DESENVOLVIMENTO

**Estado:** CI básico funciona. Release pipeline sofisticada (Docker multi-arch, SBOM, cosign). Falta formatação, linting no CI, e pre-commit hooks.

**Maturidade:** B-

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| PD1 | Média | S | **CI só corre `pytest -q`** — sem ruff lint, sem mypy type-check (pyproject.toml configura mas CI não corre) | Acidental | `.github/workflows/ci.yml:22` |
| PD2 | Média | S | **Sem pre-commit hooks** — pyproject.toml lista pre-commit mas não há .pre-commit-config.yaml | Acidental | `pyproject.toml:73` |
| PD3 | Média | S | **CI corre em ubuntu-latest com Python 3.11** mas project declara suporte a 3.12 | Acidental | `.github/workflows/ci.yml:12` |
| PD4 | Baixa | S | **Sem branch protection** — branch main sem required reviews | Inferência | Pela ausência de config |

### Recomendações
1. Adicionar ruff e mypy ao CI
2. Criar .pre-commit-config.yaml
3. Testar com Python 3.12 na CI

---

## 2.9 COERÊNCIA/COESÃO

**Estado:** Boa no geral. Padrões consistentes (structlog, dataclasses, async). Algumas inconsistências.

**Maturidade:** B

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| CC1 | Média | S | **Mistura de `logging` stdlib e `structlog`** — ui/api/main.py usa `logging.getLogger`, módulos usam `structlog.get_logger` | Acidental | `ui/api/main.py:24`, `core/event_bus.py:21` |
| CC2 | Baixa | S | **Alguns módulos usam `Path.mkdir(parents=True, exist_ok=True)` no `__init__`**, outros aceitam output_dir como param | Acidental | `modules/wifi/attacks.py` vs `modules/reporting/generator.py` |
| CC3 | Baixa | S | **Import duplicado em core/__init__.py** — `ProcessManager` importado duas vezes | Acidental | `core/__init__.py:30-31` |

### Recomendações
1. Padronizar logging: structlog em todo o código
2. Criar conftest.py com fixtures partilhadas para testes

---

## 2.10 QUALIDADE E LEGIBILIDADE

**Estado:** Bom. Código é legível, bem estruturado, com type hints. Alguns monolitos.

**Maturidade:** B+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| Q1 | Média | M | **Ficheiros monolíticos:** attacks.py (940 LOC), network/__init__.py (1108 LOC), storage.py (949 LOC) | Acidental | Medição direta |
| Q2 | Média | S | **~206 blocos `except Exception` ou `except:`** — many overly broad catches | Acidental | `rg -c "except" src/` |
| Q3 | Baixa | S | **Hardcoded paths em >30 localizações** — viola zero-config philosophy | Acidental | `rg "var/lib/urban-hs" src/` |
| Q4 | Baixa | S | **Números mágicos** — `max_output_mb: int = 100`, `max_size: int = 1000` (DLQ), etc. | Acidental | `core/process_mgr.py:44`, `core/event_bus.py:64` |

### Recomendações
1. Dividir ficheiros >500 LOC
2. Refinar exception handling (evitar bare except)
3. Extrair constantes para módulo de constantes

---

## 2.11 COBERTURA E ADEQUAÇÃO DE TESTES

**Estado:** Testes existentes mas com problemas significativos de execução. 45/61 passam, 6 falham, 10 errors, 2 ficheiros não recolhem (BLE/e2e).

**Maturidade:** C+

### Problemas

| # | Severidade | Esforço | Descrição | Intencional/Acidental | Evidência |
|---|-----------|---------|-----------|----------------------|-----------|
| T1 | Alta | M | **11/61 testes não executam** — 2 ficheiros não recolhem (BLE/e2e) devido a dbus import, 9 erros de PermissionError | Acidental | Saída pytest |
| T2 | Alta | S | **Testes hardcoded a criar dirs em /var/lib/urban-hs** — falham sem root | Acidental | `tests/test_wifi_module.py:316` |
| T3 | Média | S | **Testes de API falham** — `/healthz` retorna 404 (router prefix errado) | Acidental | `test_api_smoke.py:18` |
| T4 | Média | S | **Sem conftest.py** — fixtures duplicadas entre ficheiros | Acidental | Ausência de `tests/conftest.py` |
| T5 | Média | S | **Sem coverage report no CI** — pyproject.toml configura mas CI não corre `--cov` | Acidental | `.github/workflows/ci.yml` |
| T6 | Baixa | S | **Testes E2E dependem de mac80211_hwsim** — nunca executam em CI | Intencional | `tests/test_e2e.py` |
| T7 | Baixa | S | **Sem testes para:** reporting, gpg_evidence, credential, exploit runner, mqtt, esp32, ssid_confusion, bt_hid, hid | Acidental | Cobertura parcial |

### Recomendações
1. Criar conftest.py com fixtures partilhadas (tmp_dir, mock_config)
2. Aceitar output_dir como parâmetro em todos os módulos
3. Adicionar --cov ao CI
4. Adicionar testes para módulos sem cobertura
5. Mock dbus para testes BLE em CI

---

# FASE 3 — Operacional e Transversal

## 3.1 Reprodutibilidade

**Setup do zero:**

1. `git clone` → OK
2. `python3 -m venv .venv` → **FALHOU** — venv existente tinha Python 3.14 sem pip
3. Criado novo venv com `uv venv --python 3.11 .venv-test` → OK
4. `uv pip install -e ".[dev]"` → **FALHOU** — `gpg` package precisa de `libgpgme-dev` (headers C)
5. Workaround: instalar deps exceto `gpg` e `weasyprint`, depois `pip install -e . --no-deps` → OK
6. `pytest tests/` → **45 pass, 6 fail, 10 errors**

**Comando exato para reprodução:**
```bash
uv venv --python 3.11 .venv-test
source .venv-test/bin/activate
uv pip install aiosqlite redis pydantic pydantic-settings python-dotenv watchfiles keyring structlog rich textual typer fastapi uvicorn websockets python-jose passlib python-multipart bleak dbus-fast scapy python-nmap cryptography pyyaml tomli tomli-w prometheus-client psutil jinja2 markdown python-dateutil uuid6 orjson tqdm paho-mqtt manuf httpx
uv pip install -e "." --no-deps
uv pip install pytest pytest-asyncio pytest-cov pytest-mock
pytest tests/ -q
```

**Resultado:** O projeto **não compila nem corre limpo** a partir de clone sem intervenção manual.

## 3.2 Dependências

**pyproject.toml declara 34 dependências runtime + 7 dev + 3 docs.**

| Dependência | Risco | Notas |
|------------|-------|-------|
| `gpg>=1.17.0` | **Alta** — precisa de libgpgme-dev (C headers) | Falha em build sem system deps |
| `weasyprint>=61.2` | **Alta** — precisa de libpango, libcairo | Pesada para Raspberry Pi |
| `dbus-fast>=2.8.0` | **Média** — precisa de libdbus-1-dev | Falha em CI sem system deps |
| `redis>=5.0.0` | **Baixa** — declarada mas não usada | Dead dependency |
| `python-jose>=3.3.0` | **Média** — JWT mas auth não implementado | Prematuro |
| `passlib>=1.7.4` | **Baixa** — password hashing mas auth não implementado | Prematuro |
| `keyring>=24.3.0` | **Baixa** — secrets storage, bom padrão | Usado em config.py |

## 3.3 Config/Segredos

- `config.env.example` documenta vars necessárias
- `jwt_secret` gera fallback automático (inseguro — vê S2)
- `metasploit rpc_pass` força raise se vazia (bom)
- **Nenhum segredo commitado** — `.gitignore` exclui `*.env`, `config.env`
- **Histórico git:** commit `d923490` remove PII explicitamente — bom sinal

## 3.4 Ambiente/Deployment

- **Dockerfile.arm64:** multi-stage build funcional (147 linhas)
- **Docker Compose:** 6 serviços (dev, prod, redis, gpsd, prometheus, grafana, nginx)
- **systemd service:** bem configurado com security hardening (NoNewPrivileges, ProtectSystem, CapabilityBoundingSet)
- **scripts/bootstrap_chroot.sh:** 299 linhas, precisa de root
- **Release workflow:** sofisticada (Docker multi-arch + SBOM + cosign)

---

# FASE 4 — Síntese para Decisão

## Sumário Executivo

O Urban Hack Sentinel é um projeto ambicioso e notavelmente completo para a sua idade (~14 meses). A arquitetura modular é sólida — event bus, plugin system, HAL, e três interfaces (CLI/TUI/Web) estão funcionais. A maioria dos módulos de ataque está implementada com lógica real, não apenas casca. A documentação é generosa e bilingue. A release pipeline é sofisticada (Docker multi-arch, SBOM, cosign signing).

Contudo, o projeto tem vulnerabilidades de segurança críticas para a sua missão: a API não tem autenticação, o jwt_secret gera fallback inseguro, e não existe rate limiting. O venv está quebrado (Python 3.14 sem pip), os testes falham em 26% dos casos (16/61), e há stubs disfarçados de implementação (exploit runner, credential validation). O bash script legado de 584 linhas duplica funcionalidade Python. Há 34 dependências runtime incluindo `gpg` e `weasyprint` que precisam de headers C, tornando o setup doloroso.

## Top 10 Problemas por Prioridade

| # | Problema | Risco | Esforço | Intencional/Acidental |
|---|----------|-------|---------|----------------------|
| 1 | **API sem autenticação** — qualquer um na rede executa ataques | Crítico | M | Acidental |
| 2 | **jwt_secret fallback inseguro** — regenera a cada startup | Crítico | S | Acidental |
| 3 | **venv quebrado** — Python 3.14 sem pip, setup não funciona do zero | Alto | S | Acidental |
| 4 | **26% dos testes falham** — PermissionError, 404, dbus import | Alto | M | Acidental |
| 5 | **Exploit runner é stub** — TODO no código | Alto | L | Acidental |
| 6 | **Hardcoded paths >30** — impossível testar sem root | Médio | M | Acidental |
| 7 | **Sem CI lint/typecheck** — ruff e mypy configurados mas não correm | Médio | S | Acidental |
| 8 | **Ficheiros monolíticos** — attacks.py 940 LOC, network 1108 LOC | Médio | L | Acidental |
| 9 | **Redis declarado mas não usado** — dead dependency | Médio | S | Acidental |
| 10 | **Documentação divergente** — React vs HTMX, auth documentado mas não existe | Médio | S | Acidental |

## Quick-Wins (alto impacto, baixo esforço)

1. **Criar conftest.py** com fixtures partilhadas (tmp_dir) — resolve 9 errors de teste
2. **Fix router prefix /healthz** — resolve 2 test failures
3. **Adicionar ruff + mypy ao CI** — 5 minutos de config
4. **Remover `gpg` das deps obrigatórias** (ou conditional) — resolve setup failure
5. **Marcar stubs explicitamente** com `# STUB` ou `raise HTTPException(501)` — evita confusão
6. **Consolidar config.env.example** (remover duplicado)

## Grandes Obras (alto impacto, alto esforço)

1. **Implementar auth na API** — Bearer token mínimo, middleware
2. **Refatorar hardcoded paths** — extrair para Config, aceitar override
3. **Dividir monolitos** — attacks.py, network/__init__.py
4. **Integrar Redis** ou remover das dependências
5. **Setup do zero funcional** — resolver dependências C ou documentar

## HOTSPOTS (ficheiros mais problemáticos × churn)

| Ficheiro | Problemas | Churn |
|----------|-----------|-------|
| `modules/wifi/attacks.py` | Monolítico 940 LOC, hardcoded paths, 34 classes | 3 commits |
| `modules/network/__init__.py` | Monolítico 1108 LOC | 3 commits |
| `ui/api/main.py` | Sem auth, deprecated API, /healthz 404 | 6 commits |
| `modules/ble/exploit_chain.py` | D-Bus NoneType crash, stubs | 6 commits |
| `core/storage.py` | Sem Redis, hardcoded paths | 2 commits |
| `modules/exploit/runner.py` | TODO stub | 1 commit |
| `modules/credential/manager.py` | NotImplementedError | 2 commits |
| `tests/test_wifi_module.py` | PermissionError, hardcoded paths | — |

## Pressupostos

1. O projeto é mantido por um developer solo (Andreas_Catarinus) com assistência de AI
2. O bash script legado (`urban_hack_sentinel.sh`) pode ser mantido para backward compatibility
3. Hardware real (Alfa AWUS036ACH, Pi 5) não está disponível neste ambiente de teste
4. A branch principal é `andreas/catarinus` (baseado no git log)

## Perguntas em Aberto

1. O bash script `urban_hack_sentinel.sh` ainda é suportado ou deve ser archived?
2. A integração Redis está planeada para quando?
3. A API vai ter auth antes de exposição pública?
4. O exploit runner vai ser implementado ou removido?
5. O React PWA planeado foi substituído por HTMX ou ainda está no roadmap?

## Roteiro Sugerido

### Imediato (esta semana)
- Criar conftest.py e fix testes de PermissionError
- Fix /healthz endpoint
- Adicionar ruff/mypy ao CI
- Marcar stubs explicitamente

### Curto prazo (este mês)
- Implementar auth básica na API (Bearer token)
- Refatorar hardcoded paths → Config
- Remover ou conditionalizar gpg/weasyprint
- Adicionar --cov ao CI

### Estrutural (trimestre)
- Dividir monolitos (attacks.py, network/)
- Implementar ou remover exploit runner e credential validation
- Integrar Redis ou remover
- Setup do zero completamente funcional
