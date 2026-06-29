# Fase 10 — UI de Selecção de Ataques

> Objetivo: dar ao operador uma interface onde consegue ver módulos disponíveis, selecionar ataques, confirmar execução e acompanhar output em tempo real — tanto na TUI (Textual) como no frontend web.

---

## Escopo

- **TUI** (`urban-hs-tui`): separadores por categoria, botões de ataque, modais de confirmação, widget de terminal integrado.
- **Web UI** (`urban-hs-server`): frontend alinhado com a API existente, mesmos controlos, output em tempo real via WebSocket.
- **Backend**: reaproveitar endpoints e event bus já existentes; só adicionar o que faltar para ligar UI → execução.

Fora de scope desta fase: dry-run avançado, agendamento de ataques, persistência de preferências de UI.

---

## Estrutura de Navegação

```
┌─────────────────────────────────────────────────┐
│  URBAN HACK SENTINEL v3          status: idle    │
├──────────┬──────────┬──────────┬─────────────────┤
│ Wi-Fi    │ BLE      │ Network  │ System / Logs   │  ← separadores
├──────────┴──────────┴──────────┴─────────────────┤
│                                                 │
│            CONTEÚDO DO SEPARADOR SELECIONADO     │
│                                                 │
└─────────────────────────────────────────────────┘
```

Cada separador mostra:
- lista de ações possíveis (ataques / scans) como botões/linhas clicáveis
- estado atual da execução (idle / running / completed / error)
- barra de progresso ou indicador simples enquanto em execução

---

## Tasks

### T10.1 — Inventário dinâmico de ataques
**Objetivo**: a UI já não tem ataques hardcoded; lê automaticamente os módulos registados no plugin manager e categoriza-os por tipo.

**Critérios de aceitação**:
- TUI lista automaticamente todos os módulos com `plugin_type = SCANNER` ou `EXPLOIT`.
- Mudar o registry (adicionar plugin) atualiza a UI sem alterar código da camada de apresentação.
- Web UI recebe a mesma lista via `GET /api/v1/modules`.

**Implementação**:
- Novo endpoint `GET /api/v1/attacks` que agrupa módulos por categoria.
- `urban_hs.modules.list_modules()` já devolve o dicionário necessário; só falta expô-lo.

**Testes**:
- `tests/test_attacks_inventory.py`: scaffold com 2 testes.
  - `test_list_attacks_returns_grouped_modules`: valida que `/api/v1/attacks` devolve lista agrupada por categoria.
  - `test_attack_inventory_matches_registry`: valida que cada item inclui `name`, `plugin_type`, `description`.

### T10.2 — TUI: separadores + botões de ataque
**Objetivo**: ecrã navegável com separadores por categoria e botões por ataque.

**Layout mockup (Textual)**:
```
┌─ TabBar ─────────────────────────────────────────┐
│ [Wi-Fi] [BLE] [Network] [System]                 │
├──────────────────────────────────────────────────┤
│                                                  │
│  Wi-Fi                                           │
│  ┌──────────────────────────────────────────┐   │
│  │ Scan                    [Executar Scan]  │   │
│  │ PMKID Capture          [Executar PMKID]  │   │
│  │ WPS Pixie Dust         [Executar Pixie]  │   │
│  │ Deauth                 [Executar Deauth] │   │
│  └──────────────────────────────────────────┘   │
│                                                  │
│  Estado: idle                                    │
└──────────────────────────────────────────────────┘
```

**Critérios de aceitação**:
- Cada separador filtra apenas módulos da categoria correspondente.
- Botões têm ação; clicar em "Executar X" abre modal de confirmação.
- TUI continua a arrancar sem erros no Pi.

**Testes**:
- `tests/test_tui_tabs.py`: scaffold com 1 teste de smoke (import da app).
- Smoke test manual documentado em `docs/SMOKE_TUI.md` para validar interação no Pi.

### T10.3 — TUI: modal de confirmação
**Objetivo**: forçar confirmação antes de executar qualquer ataque, com descrição do que vai acontecer.

**Layout mockup**:
```
╭─ Confirmar execução ─────────────────────────────╮
│                                                  │
│  Ataque: Captura PMKID                           │
│  Descrição: Captura PMKID client-less via        │
│  hcxdumptool na interface wlan1.                 │
│                                                  │
│  ⚠️ Este ataque envia pacotes na rede.           │
│                                                  │
│         [Cancelar]  [Confirmar e Executar]        │
╰──────────────────────────────────────────────────╯
```

**Critérios de aceitação**:
- Modal mostra nome, descrição e avisos do módulo.
- `Cancelar` fecha modal sem efeito colateral.
- `Confirmar` dispara execução e publica evento no event bus.

**Testes**:
- `tests/test_tui_confirm_modal.py`: scaffold com 1 teste unitário (render do modal sem crash).

### T10.4 — TUI: widget de terminal integrado
**Objetivo**: mostrar output em tempo real do comando em execução, como um terminal dentro da TUI.

**Layout mockup**:
```
┌─ Terminal ───────────────────────────────────────┐
│ [Scan Wi-Fi] running...                         │
│ $ hcxdumptool -i wlan1 -o /tmp/pmkid.pcapng    │
│ [00:11:22] A varrer canal 1                     │
│ [00:11:23] Encontradas 3 redes                  │
│ [00:11:24] PMKID capturado de AA:BB:CC:DD:EE   │
│ ...                                              │
└──────────────────────────────────────────────────┘
```

**Critérios de aceitação**:
- Scroll automático (últimas linhas visíveis).
- Eventos do event bus (`attack.stdout`, `attack.stderr`, `attack.completed`) são escritos no widget.
- Modal de confirmação desaparece quando o ataque começa.

**Testes**:
- Integração via mock do event bus em `tests/test_tui_terminal.py`: simular 3 eventos e validar que o widget atualiza.

### T10.5 — Web UI: painel de ataques alinhado com TUI
**Objetivo**: frontend com os mesmos controlos, sem duplicar lógica.

**Layout mockup (HTML)**:
```
┌─ Header ─────────────────────────────────────────┐
│ Urban Hack Sentinel v3          status: idle      │
├──────────────────────────────────────────────────┤
│ Separadores: [Wi-Fi] [BLE] [Network]             │
├──────────────────────────────────────────────────┤
│                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │ Scan     │  │ PMKID    │  │ WPS      │       │
│  │ Executar │  │ Executar │  │ Executar │       │
│  └──────────┘  └──────────┘  └──────────┘       │
│                                                  │
│  Output do terminal (scrollable):                │
│  > pronto...                                     │
└──────────────────────────────────────────────────┘
```

**Critérios de aceitação**:
- Carrega lista de ataques de `/api/v1/attacks`.
- Clicar em "Executar" pede confirmação (modal do browser).
- Output aparece em tempo real via WebSocket `/api/v1/events`.
- Responsive básico (desktop + mobile).

**Testes**:
- `tests/test_web_attacks.py`: scaffold com 1 teste (lista de ataques carrega sem erro).
- Teste manual: abrir `http://localhost:8000` e validar fluxo scan → output.

### T10.6 — Backend: endpoint de execução de ataques
**Objetivo**: permitir que a UI peça execução de um módulo específico com parâmetros opcionais.

**Endpoint novo**:
```
POST /api/v1/attacks/{attack_name}/execute
Content-Type: application/json

{
  "params": { "interface": "wlan1", "target_bssid": "AA:BB:CC:DD:EE:FF" },
  "dry_run": false
}
```

**Critérios de aceitação**:
- Valida que `attack_name` está registado no plugin manager.
- Valida `params` contra o schema do módulo (se existir); senão aceita dict livre.
- Publica `attack.started` no event bus e retorna `job_id`.
- `dry_run=true` simula execução sem correr o comando (mock).

**Testes**:
- `tests/test_attacks_execute.py`: scaffold com 3 testes.
  - `test_execute_known_attack_returns_job`: módulo registado retorna 202 + job_id.
  - `test_execute_unknown_attack_returns_404`: módulo inexistente retorna 404.
  - `test_execute_dry_run_does_not_run_command`: `dry_run=true` não invoca subprocess.

### T10.7 — Eventos padronizados no event bus
**Objetivo**: garantir que todos os módulos emitem eventos no formato esperado pela UI.

**Contrato de eventos**:
```
attack.started
  -> { "attack": "pmkid_capture", "params": {...}, "job_id": "..." }

attack.progress
  -> { "job_id": "...", "percent": 45, "message": "A varrer canal 6" }

attack.completed
  -> { "job_id": "...", "success": true, "result": {...} }

attack.error
  -> { "job_id": "...", "error": "Interface wlan1 não encontrada" }
```

**Critérios de aceitação**:
- Módulos existentes (`wifi`, `ble`, `network`) emitem eventos no formato acima.
- Router WebSocket envia JSON com `type` = nome do evento.
- TUI renderiza eventos correspondentes em widgets próprios.

**Testes**:
- `tests/test_event_contract.py`: scaffold com 2 testes.
  - `test_attack_events_have_required_fields`: valida campos mínimos em cada tipo de evento.
  - `test_event_bus_publishes_attack_completed`: simula execução e valida evento final.

### T10.8 — Integração TUI + event bus
**Objetivo**: ligar a TUI existente aos eventos publicados pelos módulos.

**Critérios de aceitação**:
- Ações da TUI (botões) disparam `POST /api/v1/attacks/{name}/execute` ou chamam direto ao event bus em modo local.
- Widget de terminal escreve linhas em tempo real sem bloqueio da UI.
- Modais e botões mantêm-se responsivos durante execução longa.

**Testes**:
- `tests/test_tui_integration.py`: scaffold com 1 teste de execução mockada.

### T10.9 — Documentação da fase 10
**Objetivo**: operador conseguir usar a UI sem abrir código.

**Conteúdo**:
- `docs/SMOKE_TUI.md` atualizado com fluxo completo (separador → botão → confirmação → output).
- `docs/API.md` atualizado com endpoint `/api/v1/attacks` + `/api/v1/attacks/{name}/execute` + contratos de eventos.
- `README.md` com screenshots ASCII ou GIFs pequenos (se possível).

**Critérios de aceitação**:
- `docs/SMOKE_TUI.md` cobre fase 10.
- `docs/API.md` inclui exemplos curl para `/api/v1/attacks`.

**Testes**:
- Revisão manual (sem pytest) para garantir que screenshots/ASCII correspondem ao código.

---

## Ordem de execução recomendada

```
T10.1 (inventário dinâmico)
  └─ T10.6 (endpoint execução)
       ├─ T10.7 (eventos padronizados)
       │    ├─ T10.2 (TUI separadores + botões)
       │    │    ├─ T10.3 (modal confirmação)
       │    │    └─ T10.4 (widget terminal)
       │    │         └─ T10.8 (integração TUI + event bus)
       │    └─ T10.5 (Web UI painel)
       └─ T10.9 (documentação)
```

---

## Testes agregados (critério de done da fase)

Pelo menos estes ficheiros devem existir e passar:
- `tests/test_attacks_inventory.py`
- `tests/test_attacks_execute.py`
- `tests/test_event_contract.py`
- `tests/test_tui_tabs.py`
- `tests/test_tui_confirm_modal.py`
- `tests/test_tui_terminal.py`
- `tests/test_tui_integration.py`
- `tests/test_web_attacks.py`

Comando de validação:
```bash
pytest tests/ -q
```

Critério de fecho da fase 10:
- Suite toda verde.
- `urban-hs-tui` arranca, navega por separadores, executa ataque mockado e mostra output.
- `urban-hs-server` arranca e `/` carrega frontend com botões funcionais.
- Eventos passam de módulo → event bus → TUI e Web UI em < 1s.
