# Plano — Branch `andreas/catarinus`

> **Objetivo**: Transformar o Urban Hack Sentinel num framework multi-arquitectura (ARM64 + x86/x64) com UI interactiva integrada, sem perder o foco de ferramenta de auditoria wireless/Bluetooth/IoT.
>
> **Filosofia**: 1 codebase, feature flags para hardware específico, UI como camada superior que abstrai a complexidade dos módulos. Zero ruído.

---

## 1. Estado Actual do Repo (auditoria real)

### O que EXISTE e funciona (base sólida)
- **Core**: `event_bus`, `scheduler`, `process_mgr`, `storage` (aiosqlite + redis), `config` (pydantic-settings), `logger` (structlog), `health` (Prometheus), `concurrency`, `memory`, `security`, `plugins`
- **Módulos com implementação significativa**:
  - `wifi/scanner.py`, `wifi/attacks.py`, `wifi/managers.py` (~2KB linhas cada)
  - `ble/fastpair.py`, `ble/exploit_chain.py`
  - `network/__init__.py` (Nmap, Nuclei, SearchSploit, RouterSploit, CameraDiscovery num único ficheiro grande)
  - `camera/enumeration.py`, `camera/vuln_check.py`
  - `metasploit/rpc.py`, `metasploit/console.py`
  - `hid/ducky.py`, `hid/gadget.py`, `hid/injector.py`
  - `mqtt.py`, `credential/manager.py`, `reporting/`
- **Docker**: `Dockerfile`, `Dockerfile.arm64`, `docker-compose.yml` (multi-stage)
- **Scripts**: `bootstrap_chroot.sh`, `release.sh`, `gen_ref_pages.py`
- **Tests**: pytest + pytest-asyncio, 3 ficheiros de teste

### O que está FALTANDO ou QUEBRADO (crítico para o teu pedido)

| # | Item | Impacto | Severidade |
|---|------|---------|------------|
| 1 | `src/urban_hs/modules/__init__.py` | Package discovery falha | 🔴 BLOCKER |
| 2 | `urban_hs.cli.main` | CLI (`urban-hs`) não arranca | 🔴 BLOCKER |
| 3 | `urban_hs.ui.api.main` | API FastAPI não arranca | 🔴 BLOCKER |
| 4 | `urban_hs.ui.tui.app` | TUI Textual não arranca | 🔴 BLOCKER |
| 5 | `urban_hs.ui/` vazia | Toda a UI inexistente | 🔴 OBJECTIVO |
| 6 | `urban_hs/plugins/` vazia | Plugin registry sem plugins | 🟡 Médio |
| 7 | Docs incompletas | 1 ficheiro em `docs/`; faltam `architecture`, `api`, `modules`, `ui`, `contributing`, `installing` | 🟡 Médio |
| 8 | `pyproject.toml` aponta para ficheiros inexistentes | `pip install -e .` cria scripts broken | 🟡 Médio |
| 9 | `Dockerfile.arm64` baseado em `python:3.11-slim` multi-arch declarado mas sem condicionais por `TARGETARCH` | x86 não tem optimizações (ex: hashcat AVX2/AVX-512, drivers `rtl8812au`/`mt7921u`) | 🟡 Médio |
| 10 | `docker-compose.yml` usa sempre `Dockerfile.arm64` e não especifica platform | Build de amd64 pode falhar em packages ARM-only | 🟡 Médio |
| 11 | `config.env.example` referenciado no README mas caminho documentação futura | Config não está centralizada em `config.yaml` como espera o código | 🟢 Baixo |
| 12 | Abstração de hardware wireless inexistente | `wifi/scanner.py` chama `iw` e `aircrack-ng` diretamente; em x86 precisamos fallback scapy puro + detecção de chipset | 🔴 BLOCKER para x86 |

---

## 2. Decisões Arquitecturais

### 2.1 Codebase única, feature flags
```python
# urban_hs/core/config.py
platform: Literal["arm64", "x86_64", "auto"] = "auto"
```

Módulos dependentes de hardware registam capacidades:
```python
# modules/wifi/plugin.py
CAPABILITIES = ["wifi_monitor", "packet_injection", "gps_serial", "bluetooth_le"]
```

O platform manager filtra módulos por capacidades disponíveis na máquina actual.

### 2.2 UI como primeira classe (não adição cosmética)
- **Textual TUI**: interface padrão para operador local (teclado + rato no Pi ou laptop)
- **FastAPI + WebSocket**: streaming de eventos para browser
- **Frontend HTML/JS**: página única servida pelo FastAPI (sem React/Vite complexidade para já — usar HTMX + Alpine.js ou vanilla JS com `lit`)
- Cada módulo publica eventos no event bus; UI subscreve via WebSocket. O operador não precisa de CLI.

### 2.3 Hardware Abstraction Layer (HAL)
```
src/urban_hs/hal/
├── __init__.py
├── platform.py          # detecção: arch, kernel, capabilities
├── wifi_backend.py      # interface abstracta + implementações
│   ├── _iw_backend.py       # Linux mac80211 (aircrack-ng)
│   ├── _scapy_backend.py    # fallback puro (monitor mode limitado)
│   └── _windows_backend.py  # npcap (futuro)
└── usb_gadget_backend.py # configfs (Linux) vs stub (x86 sem gadget)
```

---

## 3. Plano de Implementação (fases)

### FASE 0 — Arrancar a casa (sem UI, sem drama)
**Duração**: 1-2 dias  
**Meta**: Tudo compila e importa; `urban-hs --help` arranca.

1. **Criar `src/urban_hs/modules/__init__.py`**
   ```python
   """Urban Hack Sentinel v3 — Plugin Modules."""
   from urban_hs.core.plugins import PluginManager, urban_plugin
   ```
2. **Corrigir `pyproject.toml` entry points**
   - Remover ou comentar `urban-hs`, `urban-hs-server`, `urban-hs-tui`
   - Criar entry points condicionais ou stub no módulo `cli`
3. **Criar CLI mínimo** (`src/urban_hs/cli/main.py`)
   - Typer app com comando `info` (versão, arch, capabilities detectadas)
   - Comando `run` que inicializa o core
4. **Validar importação de todos os módulos**
   - Script `python -c "import urban_hs; import urban_hs.modules.*"` para detectar erros de importação
5. **Mover `network/__init__.py` para estrutura mais granular**
   - `network/scanner.py`, `network/nuclei.py`, `network/camera.py` para não ter 1100 linhas num ficheiro

### FASE 1 — UI Interativa (a tua prioridade)
**Duração**: 3-4 dias  
**Meta**: UI funcional que integra módulos existentes.

#### 1.1 Backend API (`src/urban_hs/ui/api/main.py`)
- FastAPI com lifespan `init_core` + `shutdown_core`
- Endpoints REST:
  - `GET /api/v1/system/info` (arch, capabilities, status)
  - `GET /api/v1/devices` (lista devices do storage)
  - `POST /api/v1/wifi/scan` (dispara scan, devolve job_id)
  - `POST /api/v1/ble/scan`
  - `POST /api/v1/network/scan`
  - `GET /api/v1/jobs/{id}` (status + resultado polling)
- WebSockets:
  - `/ws/events` (event bus em tempo real)
  - `/ws/logs` (stream de logs)
  - `/ws/metrics` (Prometheus scrape simplificado)

#### 1.2 TUI Textual (`src/urban_hs/ui/tui/app.py`)
- Header: logo + system status (arch, interface, ram)
- Sidebar: tabs — WiFi, BLE, Network, Metasploit, HID, Reports, Config
- Painel principal:
  - **WiFi tab**: botões para scan/PMKID/WPSPixie/Deauth; tabela de redes descobertas; botão "Attack" com modal de confirmação; widget de terminal scrollable que mostra output dos ataques em tempo real via event bus.
  - **BLE tab**: scan Fast Pair, lista dispositivos, botão "Test WhisperPair Vulnerability"
  - **Network tab**: input de alvo + select scan type (host/port/os/vuln), tabela de resultados
  - **Logs tab**: terminal virtual com log level filter
- Footer: barra de status com eventos em tempo real

#### 1.3 Frontend Web (`src/urban_hs/ui/web/`)
- Uma página `index.html` servida pelo FastAPI (static mount)
- HTMX + Alpine.js (zero build step)
- Cards para cada módulo, botões grandes, área de output tipo terminal
- Funciona em browser no telemóvel ou desktop

#### 1.4 Integração Terminal↔UI
- O event bus é o único canal: módulos publicam `stdout`/`stderr`/`progress`/`result`
- TUI subescreve e actualiza widgets
- API transforma eventos em JSON para WebSocket
- Frontend recebe JSON e escreve no DOM

### FASE 2 — Portabilidade x86/x64
**Duração**: 2-3 dias  
**Meta**: Multi-arch Docker + detecção de hardware.

1. **Hardware Abstraction Layer**
   - `hal/platform.py`: detecta `arch`, `release`, capabilities (se rootless, net_admin, net_raw)
   - `hal/wifi_backend.py`: interface com métodos `scan()`, `deauth()`, `capture_handshake()`, `inject()`
   - Implementações existentes (`iw` + `aircrack-ng`) herdam desta interface
   - Nova implementação `scapy_backend` para x86 sem drivers monitor mode
2. **Docker multi-arch real**
   - `Dockerfile.arm64` mantido para Pi
   - Nova `Dockerfile.amd64` com:
     - packages x86: `hashcat` (nvidia-openjdk-cuda ou intel drivers opcionais), `rtl8812au-dkms`/`mt7921u-dkms` (instaláveis via dkms)
     - `TARGETARCH` conditional no build
   - `docker-compose.yml` actualizado com `platform: linux/amd64` quando detectado
3. **Testes de compilação**
   - Build com `docker buildx build --platform linux/amd64`
   - Verificar que `apt-get install` com `TARGETARCH=amd64` funciona

### FASE 3 — Polish + Framework
**Duração**: 2 dias  
**Meta**: Fechar o loop.

1. `src/urban_hs/modules/__init__.py` finalizado com plugin discovery
2. `plugins/` com 2-3 plugins exemplo
3. Docs mínimas para UI (screen, como usar)
4. Releases GitHub Actions com `pytest` + `ruff` + `mypy`

---

## 4. Ordem de Execução Recomendada

```
FASE 0 (arrancar a casa)
  └── FASE 1 (UI)
       └── FASE 2 (x86)
            └── FASE 3 (polish)
```

**Porquê?**
- A UI é o que tu pediste. Sem entry points funcionais, não consegues testar a TUI nem a API.
- A portabilidade x86 depende de uma UI que funcione para validar.
- O FASE 0 é fundamental: se importações quebram, tudo o resto casca.

---

## 5. Próximos Passos Imediatos (esta semana)

1. **Criar `src/urban_hs/modules/__init__.py`**
2. **Criar `src/urban_hs/cli/main.py` stub funcional (`info`, `run`)**
3. **Corrigir `pyproject.toml` entry points para os novos caminhos**
4. **Criar `src/urban_hs/ui/api/main.py` com lifespan + /api/v1/system/info**
5. **Criar `src/urban_hs/ui/tui/app.py` com 2 tabs funcionais (System, WiFi)**

---

## 6. Entregáveis por Fase

| Fase | Entregável | Local |
|------|-----------|-------|
| 0 | `urban-hs info` e `urban-hs run` funcionam | repo |
| 1 | TUI navegável com WiFi scan integrado | repo |
| 1 | API REST + WebSocket em localhost:8000 | repo |
| 1 | Frontend browser em localhost:8000/ui | repo |
| 2 | `docker buildx build --platform linux/amd64` bem-sucedido | docker/ |
| 2 | Detecção automática de capabilidades no arranque | HAL |
| 3 | Docs MkDocs preenchidas | docs/ |

---

## 7. Notas Importantes

- **Não vamos reescrever módulos existentes.** A WiFi/BLE/Network/Camera codebase já tem conteúdo substancial. Vamos só organizar melhor os `__init__.py` e adicionar a camada de UI em cima.
- **Frontend web minimalista.** Sem React/Vite/Snowpack para já. Uma página HTML + HTMX + Alpine.js é suficiente para a primeira versão interactiva. Se precisares de mais, evoluímos para Vite depois.
- **Hardware x86 não é drop-in.** Sem monitor mode via `aircrack-ng` (precisa drivers específicos), vamos activar o modo "passive_scapy" automaticamente quando `iw` não suporta a interface detectada.
- **O chroot Alpine (Sprint 4)** permanece funcional em ambas as arquitecturas; o que muda é o Dockerfile base.

---

*Documento de trabalho — será actualizado à medida que implementamos.*
