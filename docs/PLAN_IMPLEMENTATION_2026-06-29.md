# Plano de Implementação — 2026-06-29
## Urban Hack Sentinel (branch `andreas/catarinus`)

**Objectivo**: fechar os 10 issues pendentes em ordem estrita de prioridade, com commits pequenos e verificáveis, sem saltar fases.

---

## 1. Matriz Prioridade × Esforço

| # | Issue | Prioridade | Esforço | Depende de |
|---|-------|-----------|---------|------------|
| 1 | Bug `/api/v1/network/scan` 500 | **P0** | Baixo | — |
| 2 | Commit/push das alterações staged | **P0** | Baixo | #1 |
| 3 | Testes de integração API + HAL com Alfa | **P1** | Médio | #2 |
| 4 | Port x86 Docker multi-arch | **P1** | Médio | #2 (paralelizável com #3) |
| 5 | Documentação (README + docs) | **P2** | Baixo | — |
| 6 | Integração UI–event bus (websockets/SSE) | **P2** | Médio | #2 |
| 7 | Validar TUI (`urban-hs-tui`) no Pi | **P2** | Baixo | #2 |
| 8 | Validar BLE integrado Pi (Fast Pair/WhisperPair) | **P3** | Médio | #7 |
| 9 | Testes unitários/integração HAL, CLI, API, TUI | **P2** | Médio | #3 |
| 10 | Fases 2 e 3 do `PLAN_X86_UI.md` | **P3** | Alto | #4, #6, #9 |

---

## 2. Sequência de Fases

### Fase 0 — Documentação (#5)

#### 0.1. Actualizar README e docs
- **Arquivos**: `README.md`, `docs/PLAN_X86_UI.md`, `docs/index.md`, `MASTER_PLAN.md`
- **Passos**:
  1. Adicionar secções: "Instalação", "Docker multi-arch", "API", "TUI", "Hardware suportado".
  2. Documentar restrições: Alfa AWUS036ACH (wlan1), BLE integrado com limitações.
  3. Corrigir links quebrados em `docs/index.md`.
  4. Actualizar `MASTER_PLAN.md` para reflectir arquitectura actual (HAL + UI + x86 port).
  5. Adicionar troubleshooting (ex: `dbus` no container, permissões `/var/log/urban-hs`).
- **Critério de aceitação**:
  - README descreve como correr em Pi e em x86.
  - `docs/index.md` não tem links quebrados.
- **Esforço**: Baixo.

---

### Fase 1 — Fechar blocker actual (#1, #2)

#### 1.1. Fix `/api/v1/network/scan` 500
- **Arquivos**: `src/urban_hs/ui/api/routers/network.py`, `src/urban_hs/modules/ble/exploit_chain.py`
- **Passos**:
  1. Remover import eager de `ble` em `modules/__init__.py` (parcialmente feito; verificar patches anteriores).
  2. Corrigir fallback `dbus` em `exploit_chain.py` para não atribuir `None` a `dbus.mainloop`.
  3. Garantir que o handler de `network/scan` aceita `{}` (corpo vazio) usando defaults.
- **Critério de aceitação**:
  - `docker build` conclui sem erro.
  - Container arranca; `POST /api/v1/network/scan` com `{}` e com corpo completo retornam `200` + `job_id`.
- **Esforço**: Baixo.

#### 1.2. Commit e push das alterações staged
- **Passos**:
  1. `git add` todos os ficheiros modificados/criados.
  2. `git commit -m "fix: network scan 500, dbus fallback, modules lazy import"`
  3. `git push origin andreas/catarinus`
- **Critério de aceitação**: remote reflect os mesmos commits que o repo local.
- **Esforço**: Baixo.

---

### Fase 2 — Testes com hardware (#3) — paralelizável com 3

#### 2.1. Testes de integração da API com HAL (Alfa AWUS036ACH)
- **Arquivos**: `tests/test_api_integration.py`, `tests/test_wifi_hal.py`
- **Passos**:
  1. Escrever teste de API que:
     - Arranca servidor FastAPI em thread (`TestClient`).
     - Verifica `GET /api/v1/wifi/interfaces` devolve interfaces.
     - Verifica `POST /api/v1/wifi/scan` retorna `job_id`.
     - Confirma geração de CSV em `/var/log/urban-hs/wifi_scans`.
  2. Escrever teste da HAL WiFi:
     - Mock `iw`/`ip` para x86.
     - No Pi, testar com `wlan1` real em modo monitor.
- **Critério de aceitação**:
  - `pytest tests/ -k "integration or wifi"` passa no Pi.
  - Scan real da Alfa gera CSV com pelo menos 1 rede detectada.
- **Esforço**: Médio.

---

### Fase 3 — Port x86 Docker (#4) — paralelizável com 2

#### 3.1. Validar build multi-arch com `docker buildx`
- **Arquivos**: `docker/Dockerfile.arm64` (renomear para `Dockerfile.multistage`), `docker/docker-compose.yml`
- **Passos**:
  1. Separar blocos condicionais por `TARGETARCH` já existentes (já feitos).
  2. Testar `docker buildx build --platform linux/amd64,linux/arm64 -t urban-hs:test .`
  3. Testar run local amd64 via QEMU (se disponível) ou em VM x86.
  4. Corrigir eventuais pacotes que não existam em Debian amd64 (ex: `libffi8` é ARM-only; no amd64 é `libffi8` ou `libffi`).
- **Critério de aceitação**:
  - Build multi-arch sem erro.
  - Servidor arranca em ambas as archs.
- **Esforço**: Médio.

#### 3.2. Ajustar runtime dependencies por arch
- Verificar nomes de libs:
  - `libffi8` (arm64) vs `libffi` (amd64).
  - `libssl3` (arm64) vs `libssl3t64` ou `libssl` (amd64, Debian 12+).
- Aplicar condicional no Dockerfile se necessário.
- **Critério de aceitação**:
  - `apt-get install` não falha em nenhuma arch.
- **Esforço**: Baixo/Médio.

---

### Fase 4 — Integração UI–event bus (#6)

#### 4.1. WebSocket/SSE no FastAPI
- **Arquivos**: `src/urban_hs/ui/api/main.py`, `src/urban_hs/ui/web/index.html`
- **Passos**:
  1. Criar endpoint `/api/v1/events` (WebSocket ou SSE).
  2. Subescrever a eventos do event bus (`scan.completed`, `scan.error`, etc.) e emitir para clientes conectados.
  3. Actualizar frontend para receber eventos e actualizar DOM sem reload.
- **Critério de aceitação**:
  - Ao abrir dashboard no browser, aparecem eventos em tempo real quando um scan termina.
- **Esforço**: Médio.

#### 4.2. Botões de ataque na UI
- Conectar botões do `index.html` a endpoints da API (já existentes).
- **Critério de aceitação**:
  - Clicar "WiFi Scan" na UI dispara POST e mostra resultado na página.

---

### Fase 5 — Validar TUI (#7)

#### 5.1. Testar `urban-hs-tui` no Pi
- **Passos**:
  1. Correr `urban-hs-tui` directamente no Pi (fora do Docker) com `.venv`.
  2. Verificar que as abas renderizam e o widget de terminal mostra output.
  3. Testar interacção básica (seleccionar scan, ver eventos).
- **Critério de aceitação**:
  - TUI entra sem crash; pelo menos uma aba mostra dados reais (WiFi scan).
- **Esforço**: Baixo.

---

### Fase 6 — Validar BLE integrado (#8)

#### 6.1. Testar scanning BLE com adapter integrado do Pi 5
- **Passos**:
  1. Verificar que `bluetoothctl` e `hciconfig` estão disponíveis.
  2. Correr `GET /api/v1/ble/scan` via API.
  3. Se scanning falhar por permissões, documentar workaround (sudo ou grupos).
- **Critério de aceitação**:
  - Scan BLE retorna dispositivos OU documentação clara do bloqueio.
- **Esforço**: Médio.

---

### Fase 7 — Cobertura de testes (#9)

#### 7.1. Testes unitários HAL
- **Arquivos**: `tests/test_hal.py`
- **Passos**:
  1. Adicionar testes para HAL WiFi (`_iw_backend`, `_scapy_backend`) com mocks.
  2. Adicionar testes para HAL BLE (mock bleak).
  3. Adicionar testes para `platform.py` (fake `uname`, `os-release`).
- **Critério de aceitação**:
  - `pytest tests/ -k hal` passa 100%.
- **Esforço**: Médio.

#### 7.2. Testes de integração CLI e TUI
- CLI: usar `click.testing.CliRunner` para testar `urban-hs info` e `urban-hs modules`.
- TUI: difícil automatizar; ficar por smoke test manual documentado em `tests/README.md`.
- **Critério de aceitação**:
  - CLI: output não vazio, exit code 0.
  - TUI: smoke test checklist completado.
- **Esforço**: Baixo/Médio.

---

### Fase 8 — Fases 2 e 3 do `PLAN_X86_UI.md` (#10)

#### 8.1. Fase 2 — Portabilidade x86
- Revisar `PLAN_X86_UI.md` e implementar pontos pendentes:
  - Verificar se há código ARM-specific (`/dev/gpiomem`, `/sys/class/gpio`) que necessite de wrapper HAL.
  - Garantir que `HAL` select funciona para x86 (scapy, bleak).
- **Critério de aceitação**:
  - `docker run --platform linux/amd64 urban-hs:test urban-hs info` funciona.

#### 8.2. Fase 3 — Polimento e framework
- Revisar arquitectura:
  - Separar claramente core, HAL, modules, UI.
  - Adicionar type hints e `mypy` (opcional).
  - Adicionar `ruff`/`black` checks em CI (se houver CI).
- **Critério de aceitação**:
  - Código organizado por camadas, sem imports circulares.

---

## 3. Fluxo de Commits Recomendado

```
docs: actualizar README + arquitectura x86/UI
fix: network scan 500, dbus fallback, modules lazy import
test: integration API + HAL com Alfa AWUS036ACH
feat: docker multi-arch (linux/amd64,linux/arm64)
feat: websocket real-time events na API
test: unit HAL e smoke CLI/TUI
refactor: separação core/hal/modules/ui (fase 3)
```

---

## 4. Riscos

| Risco | Mitigação |
|-------|----------|
| `dbus-python` não compila em x86 | Manter `bleak` como default; dbus só para BlueZ nativo no futuro. |
| `libssl`/`libffi` com nomes diferentes entre Debian 12 e Bookworm | Buildomatizar por `TARGETARCH` + `VERSION_CODENAME`. |
| Bluetooth integrado do Pi não permite scanning sem sudo | Usar grupo `bluetooth` ou cap sys_admin. |
| Alfa AWUS036ACH em x86 precisa drivers diferentes | Scapy fallback já cobre chipsets não suportados por `iw`. |
| TUI não arranca no Pi por falta de terminal suportado | Documentar requisitos de terminal (`TERM=xterm-256color`). |

---

## 5. Critérios de "Feito"

Para considerar cada issue fechado:
- [ ] Código mergeado em `andreas/catarinus`.
- [ ] Build Docker succeed (local ou CI).
- [ ] Pelo menos um teste (unit ou integração) a cobrir o comportamento.
- [ ] Documentação reflect a mudança (se aplicável).

---

**Próximo passo imediato**: Fase 0.1 (actualizar documentação) → Fase 1.1 (fix `network/scan` 500) → commit/push.
