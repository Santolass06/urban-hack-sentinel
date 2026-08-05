# Correção cirúrgica — SessionScope bypass + inconsistências pós-auditoria

**Data**: 2026-07-01
**Ramo**: `andreas/catarinus`
**Commit base**: `6bee055`
**Âmbito**: 3 correções pontuais (não é sessão autónoma). Nenhum scan ativo /
ataque real foi executado — essa decisão continua a exigir confirmação
explícita do utilizador.

---

## Resumo dos resultados de teste (antes → depois)

Ambiente local sem hardware (sem `dbus`, sem `/var/lib/urban-hs`). Comando
equivalente ao CI, ignorando os ficheiros que dependem de hardware:

```
pytest tests/ --ignore=tests/test_ble_module.py \
               --ignore=tests/test_e2e.py \
               --ignore=tests/test_sprint6.py
```

| Métrica | Antes (baseline `6bee055`) | Depois |
|---------|----------------------------|--------|
| Passed  | 154 | **156** (+2 testes de guarda WiFi) |
| Skipped | 0   | 6 (testes BLE/urban_hack — ver nota) |
| Failed  | 3   | 3 (**idênticas** — pré-existentes) |

As **3 falhas são pré-existentes e ambientais**, não regressões:
`tests/test_wifi_plugin_contract.py::{test_initialize_plugin,
test_start_then_stop, test_attack_execution}` falham em
`plugin.initialize()` ao tentar `mkdir /var/lib/urban-hs` (sem permissões
neste ambiente). Ocorre **antes** de qualquer código de SessionScope.

Lint (o CI corre `ruff check src/urban_hs/`): baseline **4658** erros →
depois **4656** (−2). As alterações reduzem a dívida de lint (imports movidos
para o topo em vez de lazy). O gate de lint já estava vermelho antes desta
sessão (dívida pré-existente massiva), fora do âmbito destas correções.

---

## 1. Fecho do bypass do SessionScope  ✅ (caminho vivo provado)

### Causa raiz
`SessionScope.validate()` só era chamado no endpoint REST
`/attacks/{name}/execute` (`ui/api/routers/attacks.py`). Existiam caminhos
paralelos via event bus que executam ataques reais sem passar pelo guard.

### Alterações
- **`core/session_scope.py`** — novo singleton de processo (fonte única de
  verdade): `get_active_scope()` / `set_active_scope()`. Vive em `core` (a
  camada mais baixa) para os handlers de módulos poderem consultá-lo **sem
  depender da camada UI** e sem import circular (attacks.py importa
  `urban_hs.modules` no topo, logo um módulo a importar attacks no topo
  criaria um ciclo — `core` não tem esse problema).
- **`ui/api/routers/attacks.py`** — removido o `_session_scope` local;
  `get_session_scope()`/`set_session_scope()` passam a delegar no singleton
  de `core`; a linha `validate()` passa a ler `get_session_scope()` (o
  mesmo objeto partilhado). A API pública usada pelos testes/TUI mantém-se.
- **`modules/wifi/plugin.py:_handle_attack_request`** — guard adicionado
  **antes** de qualquer `execute_*()`: `get_active_scope().validate(bssid,
  "wifi")`. Em `PermissionError` publica `wifi.attack_denied` e retorna (o
  handler de evento não tem `HTTPException` como o router REST).
- **`modules/urban_hack.py:_handle_wifi_attack`** — mesmo guard (`wifi`).
- **`modules/urban_hack.py:_handle_ble_exploit`** — guard (`ble`, target =
  `address`) antes do corpo do exploit; em bloqueio publica
  `ble.attack_denied`. Mantido o guard de config `enable_active_attacks`
  existente (complementar, não redundante — o SessionScope vem **antes**).
- **`modules/ble/plugin.py:_handle_exploit_request`** — **extensão explícita
  aos 3 locais pedidos**: este é o handler *realmente subscrito* a
  `ble.exploit_request` (o de `urban_hack.py` é um segundo handler do mesmo
  evento). Deixá-lo aberto significaria não fechar o bypass para BLE. Guard
  idêntico adicionado. (Registado aqui para não ser uma expansão silenciosa
  de âmbito.)

Mapeamento target/categoria: valores **fixos** por handler
(`category="wifi"`/`"ble"`, `target=bssid`/`address`) — **não** se reusa o
`attack_name.split("_")` do REST, porque o payload do evento tem `type`/
`bssid`, não um `attack_name`.

### Validação — com controlo positivo (ponto crítico)
Ficheiro novo: **`tests/test_session_scope_guard.py`**. Cada cenário tem um
**controlo positivo** obrigatório, porque sem ele um assert "não executou"
também passaria pelo `if not bssid: return` pré-existente — provando nada.

- `test_wifi_attack_blocked_by_closed_scope` — scope fechado → evento
  correto (`type=deauth`, `bssid` presente) → `execute_deauth` **não** é
  chamado **E** `wifi.attack_denied` é publicado. ✅ **PASSA**
- `test_wifi_attack_allowed_by_open_scope` (**controlo positivo**) — mesmo
  evento, scope aberto para o target+wifi → `execute_deauth` **é** chamado.
  ✅ **PASSA** → prova que é o SessionScope a bloquear, não o early-return.
- 6 testes análogos para os handlers `urban_hack`/`ble.plugin` (bloqueio +
  controlo positivo) — **SKIPPED** neste ambiente (ver nota abaixo).

`tests/test_wifi_plugin_contract.py::test_attack_execution` foi atualizado
para **abrir** o scope (senão o novo guard bloqueava-o), com teardown a
repor o scope fechado para não contaminar outros testes.

### Confirmação: os handlers são os únicos chamadores de `execute_*`
`grep` a todos os chamadores de `execute_deauth/handshake/pmkid/wps_*`
(`src/`, sem testes) confirma que só os dois handlers guardados os invocam
— não há chamador direto por fora. O `cli/main.py` **não** tem comando de
execução de ataque (só `info`/`run`/`tui`/`modules`/`verify`/`seal`/
`audit-trail`). `deauth.py:181` é uma delegação **interna** (Kr00k) já a
jusante de um ataque em curso, não um ponto de entrada novo. Logo, para a
superfície de *attack_request* WiFi/BLE, o bypass está **fechado**.
(Fora de âmbito, mas registado: `camera/vuln_check.py:239` chama o
`ExploitRunner` diretamente — superfície distinta, não é o bypass
event-bus definido nesta tarefa; o ExploitRunner tem os seus próprios
guards na camada REST.)

### ⚠️ Nota crítica de honestidade sobre o alcance real do bypass
Durante a verificação descobriu-se que **o único caminho de bypass
*importável/alcançável* hoje é o `wifi/plugin.py`** — e esse está corrigido e
**totalmente provado** (controlo positivo + negativo). (Nota de precisão:
não foi verificado que `WiFiPlugin` está de facto subscrito na app em
execução; a afirmação é sobre importabilidade + funcionamento do
handler+guard, não sobre a ligação em runtime.) Os outros dois pontos são
defesa em profundidade **atualmente inalcançável**, por dois motivos
independentes:

1. **`modules/ble/fastpair.py:231` usa `Enum` sem o importar** (falta
   `from enum import Enum`). Isto torna `urban_hs.modules.ble` — e por
   dependência `urban_hs.modules.urban_hack` — **não-importável em qualquer
   ambiente**. Bug pré-existente, independente do `dbus`. Confirmado:
   `NameError: name 'Enum' is not defined`.
2. `modules/ble/exploit_chain.py:83` usa `dbus.Interface` como anotação
   avaliada em tempo de import; com `dbus` ausente (extensão C opcional)
   dá `AttributeError`.

Consequência: os guards em `urban_hack.py`/`ble/plugin.py` são
estruturalmente **idênticos** ao guard WiFi provado, mas não podem ser
exercitados por testes até (1)/(2) serem resolvidos — daí os 6 SKIPPED. Não
os corrigi por estarem **fora do âmbito cirúrgico** destas 3 tarefas.

### Também descoberto (não corrigido — follow-ups sugeridos)
- O `_publish_attack` do TUI publica `{"attack", "params"}`, mas os handlers
  leem `payload.get("type")`/`get("bssid")`. Ou seja, **o TUI hoje nem sequer
  aciona execução real** (early-return por `bssid` ausente). O guard é
  correto para quando o contrato do payload for alinhado.
- Não existe subscritor para `ble.attack_request` (o TUI publica-o via
  `_publish_attack("ble_whisperpair")`); só `ble.exploit_request` tem
  handler.

Por estes dois motivos, **não** foi feito o "teste manual via TUI" pedido no
enunciado: mostraria "bloqueado" independentemente da correção (pelo
early-return / ausência de subscritor), exatamente o falso-positivo que o
próprio enunciado avisa ("teste passava e comportamento real divergia").

---

## 2. Campo "simulated" no caminho de scan da TUI  ✅

### Causa raiz
O TUI tem caminho de scan próprio (não passa pelos routers REST) que publica
`wifi.scan.completed` / `ble.scan.completed` / `network.scan.completed` sem o
campo `simulated`, ao contrário dos routers que sempre o incluem.

### Alterações
- **`ui/tui/app.py`** — adicionado `"simulated": False` aos 3 payloads
  (`_wifi_scan`, `_ble_scan`, `_network_scan`), alinhando o contrato de
  evento com o caminho REST.

### Sobre o `.get("simulated", False)` defensivo
Procura em todo o `src/` por consumidores que façam `payload["simulated"]`:
**nenhum existe**. As únicas referências a `simulated` são produtores
(routers/TUI) e o parâmetro de `_audit_log`. Logo não havia risco de
`KeyError` e não havia nada para "endurecer".

### Validação
`pytest tests/test_tui_phase10.py tests/test_event_contract.py` → **3
passed**. Suite completa sem regressões (ver tabela).

---

## 3. Reconciliação do rate limiting pós-merge  ✅ (confirmado; decisão registada)

### O que existe
Duas camadas coexistem por design (defesa em profundidade):

| Camada | Onde | Limite | Âmbito | Resposta |
|--------|------|--------|--------|----------|
| **Global** `RateLimitMiddleware` | `main.py:128` (Sprint 8A) | `cfg.api.rate_limit_per_minute` = **60/min** por IP | **Todos** os pedidos/endpoints | 429 `Too Many Requests` (texto) |
| **Por-endpoint** `@limiter.limit` (slowapi) | 4 endpoints de escrita | **10/min** por IP e por endpoint | attacks/execute, wifi/ble/network scan | 429 via `_rate_limit_exceeded_handler` |

### Há conflito? Não — verificado empiricamente
- O middleware global é uma camada **ativa e independente**: 65 GETs a
  `/healthz` (endpoint **sem** decorator) → primeiro **429 no pedido #61**,
  confirmando o limite global de 60/min.
- O decorator por-endpoint dispara ao 11.º pedido de escrita (10/min),
  provado por `test_api_integration::test_wifi_scan_rate_limited_after_threshold`
  e `test_attacks_execute::test_execute_rate_limit_triggers_429` (ambos
  passam).

Composição é **monótona ("mais restritivo ganha")**: se **qualquer** das
duas cestas esgotar, o pedido recebe 429. Não há caso "uma permite, a outra
nega, resultado depende da ordem" — ambas convergem para 429. Ordem real:
o middleware global (adicionado por último → corre primeiro/outermost)
antecede o decorator (no endpoint). Para endpoints de escrita o teto
efetivo é 10/min (10 < 60); o global 60/min é um backstop que também cobre
leituras e `auth/token`.

### Valores diferentes (60 vs 10) — decisão
**Prevalência decidida: manter ambas as camadas.** São âmbitos
deliberadamente diferentes, não um limite duplicado por engano:
- **10/min por endpoint de escrita** = teto apertado para ações sensíveis;
- **60/min global por IP** = travão amplo contra abuso agregado (inclui
  leituras e `auth/token`, que os decorators não cobrem).

Não se removeu nenhuma camada (o enunciado pede confirmação da intenção do
Sprint 8A antes de remover — commit `11772a4` introduziu o middleware
global explicitamente; é intencional).

### Observações menores (não corrigidas — fora de âmbito)
- **Mensagem** difere consoante a camada que bloqueia (global: `"Too Many
  Requests"`; slowapi: `"Rate limit exceeded: 10 per 1 minute"`). O
  **status é sempre 429** (inequívoco); só o corpo difere. Cosmético.
- O `_rate_buckets` do middleware global é global-de-processo e **não** é
  reposto entre testes (os fixtures só fazem `limiter.reset()` do slowapi).
  Se alguma vez uma suite fizer >60 pedidos do mesmo client-host dentro da
  janela de 60s, poderá haver flakiness. Hoje está abaixo do limiar. Vale
  registar como risco latente.

---

## Ficheiros alterados

| Ficheiro | Fix | Natureza |
|----------|-----|----------|
| `src/urban_hs/core/session_scope.py` | 1 | Novo singleton partilhado |
| `src/urban_hs/ui/api/routers/attacks.py` | 1 | Delega no singleton de core |
| `src/urban_hs/modules/wifi/plugin.py` | 1 | Guard (caminho vivo, provado) |
| `src/urban_hs/modules/urban_hack.py` | 1 | Guard ×2 (def. profundidade) |
| `src/urban_hs/modules/ble/plugin.py` | 1 | Guard (def. profundidade) |
| `src/urban_hs/ui/tui/app.py` | 2 | `simulated: False` ×3 |
| `tests/test_session_scope_guard.py` | 1 | **Novo** — 8 testes (2 vivos + 6 skip) |
| `tests/test_wifi_plugin_contract.py` | 1 | Abre scope + teardown |

> **Estado git**: alterações **não** commitadas — a aguardar aprovação do
> utilizador. Os hashes de commit serão preenchidos no momento do commit.

## Follow-ups recomendados (fora do âmbito destas 3 correções)
1. `from enum import Enum` em `modules/ble/fastpair.py` — desbloqueia o
   módulo BLE inteiro e permite correr os 6 testes de guarda BLE/urban_hack.
2. `from __future__ import annotations` (ou `"dbus.Interface"` em string) em
   `modules/ble/exploit_chain.py` — evita o crash de import sem `dbus`.
3. Alinhar o contrato de payload do TUI `_publish_attack` (`type`/`bssid`)
   com os handlers, e adicionar subscritor para `ble.attack_request`, para
   que o caminho TUI→ataque seja realmente funcional (e então guardado).
