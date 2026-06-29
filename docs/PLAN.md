# Urban Hack Sentinel v3 — Plano de Execução

> Branch: `andreas/catarinus`  
> Estado: fases 0-9 concluídas. Próxima entrega: fase 10 (UI de selecção de ataques)

---

## 1. Objectivo

Transformar o UHS numa ferramenta multi-arquitectura (`linux/arm64`, `linux/amd64`) com UI interativa para selecção e execução de ataques, mantendo codebase única via HAL (Hardware Abstraction Layer).

---

## 2. Estado Actual

### 2.1 O que já funciona (fases 0-9)
- Core: event bus, scheduler, process manager, storage (aiosqlite), config, logger, health checks, plugin registry com 2 exemplos (`example_sniffer`, `example_reporter`).
- HAL: detecção automática de plataforma (`arm64`/`x86_64`); backend WiFi com fallback `iw` → `scapy`; backend BLE via `bleak`; backend Network via `nmap`; USB gadget/HID stubbed.
- Módulos com implementação significativa: `wifi`, `ble`, `network`, `metasploit`, `hid`, `mqtt`, `camera`, `reporting`, `credentials`.
- CLI: `urban-hs info`, `urban-hs modules`, `urban-hs run`.
- TUI: `urban-hs-tui` (Textual) — importável e estruturada.
- API: FastAPI + WebSocket (`/api/v1/events`) + frontend estático (`/`), com endpoints de sistema, WiFi, BLE, Network.
- Docker: multi-arch `linux/amd64,linux/arm64` com `TARGETARCH`.
- Testes: 14 passing (10 HAL + 3 API + 1 smoke) + 5 CLI smoke tests, todos determinísticos via mock de hardware.
- CI: GitHub Actions mínimo com `pytest`.

### 2.2 O que ainda falta
- UI interactiva de selecção de ataques com botões de confirmação e widget de terminal integrado.
- Validação prática no hardware real (Alfa AWUS036ACH x86, GPS, BLE).
- Cobertura de testes para TUI e plugins.
- Documentação de utilizador da UI.

---

## 3. Fases

### Fase 0 — Fundação (concluída)
- Repo estruturado, pyproject, core, HAL, CLI mínima, importações estáveis.
- Critério: importa tudo, `urban-hs info` retorna JSON válido.

### Fase 1 — Fix Blocker (concluída)
- Resolver 500 em `/api/v1/network/scan`.
- Resolver fallback `dbus` em `ble/exploit_chain.py`.
- Critério: REST OK, container arranca, testes passam.

### Fase 2 — Testes (concluída)
- HAL tests mockados, API integration, CLI smoke tests.
- Critério: 14+ testes deterministic passing.

### Fase 3 — Docker multi-arch (concluída)
- `Dockerfile.arm64`, `Dockerfile.amd64`, `docker-compose.yml` com `TARGETARCH`.
- Critério: build local para ambas as archs sem erro.

### Fase 4 — Event Bus + WebSocket (concluída)
- Router `/api/v1/events` (WebSocket) ligado ao event bus.
- Frontend alinhado a endpoints existentes.
- Critério: UI recebe eventos em tempo real.

### Fase 5 — Smoke test TUI (concluída)
- Checklist documentado em `docs/SMOKE_TUI.md`.
- Critério: import OK, TUI entra sem crash no Pi.

### Fase 6 — BLE integrado (concluída)
- Scan BLE com backend `bleak` validado no Pi 5.
- Critério: scan retorna dispositivos OU documentação clara do bloqueio.

### Fase 7 — Cobertura CLI/TUI (concluída)
- 5 CLI smoke tests via subprocess.
- Critério: `pytest tests/test_cli.py` verde.

### Fase 8 — Polish framework (concluída)
- Plugin registry com 2 plugins exemplo, docs API, CI mínimo.
- Critério: registry com 16 plugins, `docs/API.md` completo.

### Fase 9 — HAL WiFi x86 fallback scapy (concluída)
- `create_wifi_backend()` com fallback real `iw` → `scapy`.
- Critério: HAL tests passam para plataformas sem `iw`.

### Fase 10 — UI de selecção de ataques (PENDENTE)
- TUI: Tabs com botões por módulo, modais de confirmação, widget terminal integrado via event bus.
- Web: frontend com mesmos controlos e output em tempo real.
- Critério: operador consegue seleccionar ataque, confirmar, e ver output na UI.

---

## 4. Priorização

1. **Fase 10**: UI de selecção de ataques — é o core do pedido original.
2. **Hardware real**: validar com Alfa AWUS036ACH x86 + Pi BLE.
3. **Docs**: guia do utilizador para a UI e troubleshooting actualizado.

Qualquer outra fase (plugins dinâmicos via entry points, e2e completo, release automation) vem depois destas três.

---

## 5. Documentação

| Documento | Status | Função |
|-----------|--------|--------|
| `README.md` | Actualizado | Quickstart, instalação, Docker, CLI, TUI, API |
| `docs/API.md` | Mantido | Referência REST + WebSocket |
| `docs/SMOKE_TUI.md` | Mantido | Checklist de smoke test da TUI no Pi |
| `docs/MULTIARCH.md` | Mantido | Guia de build multi-arquitectura local |
| `docs/PLAN.md` | Este | Plano faseado, estado e próximos passos |
| `docs/index.md` | Mantido | Índice central da documentação |
| `docs/archive/*` | Arquivado | Documentos legados não mantidos na linha frontal |

---

## 6. Critérios Gerais de “Feito”

- Código mergeado em `andreas/catarinus`.
- Build Docker verde (`linux/amd64` e `linux/arm64`).
- Pelo menos um teste (unit ou integração) cobrindo o comportamento.
- Documentação reflecte a mudança (se aplicável).
- Nenhum import crash em ambiente limpo.
