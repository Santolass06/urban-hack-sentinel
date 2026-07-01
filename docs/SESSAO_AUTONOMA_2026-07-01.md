# Sessão Autónoma — 2026-07-01

## Estado Inicial

- **Branch:** `andreas/catarinus`
- **Testes baseline:** 109 passed, 8 warnings (pytest, `--ignore test_ble_module.py --ignore test_e2e.py`)
- **Mudanças por commitar:** 17 modified files + 3 untracked (rate_limit.py, test_ws_auth.py, msfinstall)
- **Branch divergence:** 10 local vs 12 remote commits

## Fase 0 — Levantamento

### O que foi feito
- Lidos todos os `.md` de planeamento: `MASTER_PLAN.md`, `ROADMAP.md`, `docs/PLAN.md`, `docs/PLAN_PHASE10.md`
- Feito `git log --oneline -30` e `git status` — 17 modified, 3 untracked
- Rodada suite de testes baseline — 109 passam, 2 ficheiros ignorados (dbus unavailable)
- Feito grep de rate limiting em todos os routers — confirmado em attacks/execute, wifi/scan, ble/scan, network/scan

### Descobertas

#### Example modules
- `example_reporter` e `example_sniffer` **já foram removidos** do `_MODULE_REGISTRY` na sessão anterior
- Os ficheiros `.py` ainda existem em `src/urban_hs/modules/plugins/` como referência
- Não há nada a fazer aqui — item 1 das pendências já resolvido

#### Rate limiting
- Aplicado a TODOS os endpoints REST de escrita: `attacks/execute` (10/min), `wifi/scan` (10/min), `ble/scan` (10/min), `network/scan` (10/min)
- Endpoints de leitura (`GET /info`, `GET /wifi/interfaces`, `GET /wifi/jobs`, etc.) não têm rate limiting — correto, são read-only
- `POST /api/v1/auth/token` não tem rate limiting — decidido manter assim (é localhost-only)

#### WebSocket auth
- Testado em sessão anterior com `test_ws_auth.py` — 4 testes passam
- Aceita `Authorization: Bearer` header E `?token=` query param
- Fecha com `WS_1008_POLICY_VIOLATION` (4003) se token inválido/ausente

#### Event name mismatches (descoberta crítica)
- TUI escuta: `wifi.scan_complete` → Routers emitem: `wifi.scan.completed`
- TUI escuta: `ble.scan_complete` → Routers emitem: `ble.scan.completed`
- TUI escuta: `attack.progress` → NADA emite este evento
- TUI escuta: `attack.error` → Routers emitem: `attack.completed` (com `success=False`) ou `attack.denied`
- **Resultado:** TUI nunca recebe resultados de scans feitos via API

#### Web UI bugs
- `wifiScan()` envia JSON body mas o endpoint espera query parameters → interface nunca é enviada
- `bleScan()` mesmo problema — envia body em vez de query param
- Sem reconnect logic no WebSocket
- Sem Network section na UI apesar de existir endpoint
- Sem indicador de estado do WebSocket (ligado/desligado)

#### TUI bugs
- `_publish_attack()` usa `type="wifi.attack_request"` para TODOS os ataques (inclusive BLE)
- Network scan é um stub ("Nmap scan not yet implemented")
- Attack buttons são stubs que só publicam eventos
- Acessa `bus._queue.get()` — atributo privado do EventBus

## Fase 1 — Segurança/Consistência

### Tarefas concluídas
1. ✅ Example modules removidos do registry (já feito antes)
2. ✅ Rate limiting confirmado em todos os endpoints de escrita
3. ✅ WebSocket auth confirmado (test_ws_auth.py)
4. ✅ pytest completo — 109/109

## Fase 2 — Remake da UI

### Tarefas a implementar
- [ ] Corrigir event name mismatches (alinhamento TUI ↔ routers)
- [ ] Corrigir Web UI body-vs-query-param bug
- [ ] Adicionar WebSocket reconnect ao Web UI
- [ ] Adicionar Network section ao Web UI
- [ ] Corrigir attack type bug no TUI
- [ ] Ligar network scan ao botão do TUI
- [ ] Fazer TUI usar API em vez de calls diretas ao scanner
- [ ] pytest completo

## Fase 3 — SessionScope

### Tarefas a implementar
- [ ] SessionScope dataclass com allowlist + categorias
- [ ] Integração ativa com executor de ataques
- [ ] Guard rails: scope sem allowlist bloqueia ataques ativos
- [ ] Testes: scope vazio bloqueia, allowlist permite só alvos listados, categoria errada bloqueia

## Fase 4 — Simulação Real

### Estado
- PARADO — à espera de confirmação do André antes de qualquer ataque ativo
- Scan passivo: tentar real (iw scan), fallback para simulação se não disponível

## Commits feitos
(será preenchido no final da sessão)
