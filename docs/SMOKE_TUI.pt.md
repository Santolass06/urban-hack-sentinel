# Smoke Test TUI e Guia de Testes Custom

Validação manual e orientação para desenvolver testes custom contra a camada Textual TUI.

---

## Índice

- [Ambiente](#ambiente)
- [Passos do smoke test](#passos-do-smoke-test)
- [Resultado esperado](#resultado-esperado)
- [Desenvolver testes custom](#desenvolver-testes-custom)
- [Padões de teste](#padões-de-teste)
- [Integração com CI](#integração-com-ci)

---

## Ambiente

- Anfitrião: Raspberry Pi 5 ou máquina x86/64
- Sistema: Linux (kernel 6.x recomendado)
- Terminal: `TERM=xterm-256color`
- Python: `.venv` do projecto activado

---

## Passos do smoke test

1. `cd /home/andresantos/Desktop/Projects/urban-hack-sentinel`
2. `. .venv/bin/activate`
3. `python -m urban_hs.ui.tui.app` (ou `urban-hs-tui`)
4. Confirmar:
   - O cabeçalho mostra versão + informação do sistema
   - A tab Wi-Fi mostra botões Scan e Interfaces
   - A tab BLE mostra botão Scan Fast Pair
   - A tab Network mostra botão Host Discovery
   - A tab Terminal mostra um widget de terminal vazio
5. Pressionar `Scan` na tab Wi-Fi → o log mostra evento
6. Pressionar `q` para sair

---

## Resultado esperado

- A TUI inicia sem crash
- Pelo menos uma tab mostra dados reais/eventos (scan Wi-Fi ou BLE)
- A tab Terminal faz scroll automático com novos eventos

---

## Desenvolver testes custom

A TUI usa Textual, que requer um TTY real para testes de integração completos. Os testes automáticos devem focar-se em:

- Criação da instância da app
- Composição de widgets
- Dispatch de eventos
- Métodos de ação

### Convenção de ficheiros

Coloque testes TUI em `tests/test_tui_*.py`. Use nomes descritivos:

- `tests/test_tui_phase10.py` — smoke tests da UI de ataques
- `tests/test_tui_events.py` — wiring do event bus
- `tests/test_tui_widgets.py` — composição de widgets

### Fixtures

Reutilize uma função de fábrica que devolva uma instância fresca de `TUIApp`:

```python
from urban_hs.ui.tui.app import TUIApp

def _app() -> TUIApp:
    return TUIApp()
```

Evite fixtures do pytest que devolvem a própria função wrapper; instancie `TUIApp()` directamente no teste.

---

## Padões de teste

### 1. Verificar que ações de ataque existem

```python
def test_tui_app_has_attack_actions() -> None:
    app = _app()
    assert hasattr(app, "_wifi_deauth")
    assert hasattr(app, "_wifi_handshake")
    assert hasattr(app, "_ble_whisperpair")
```

### 2. Mock `query_one` para dispatch de eventos

`query_one` requer uma DOM montada. Monkeypatch com um widget falso:

```python
def test_tui_event_handler_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    calls: list[str] = []

    class FakeLog:
        def write_line(self, line: str) -> None:
            calls.append(line)

    fake = FakeLog()
    monkeypatch.setattr(app, "query_one", lambda sel, cls, *args, **kwargs: fake)

    from urban_hs.ui.tui.app import EventMessage
    message = EventMessage(event_type="attack.started", payload={"attack": "x"})
    app.on_event_message(message)

    assert any("[yellow]START[/yellow]" in line for line in app._attack_log)
```

### 3. Testar caminho de publicação sem rede

Substitua `get_event_bus` ou `bus.publish` para capturar eventos:

```python
def test_tui_publish_attack(monkeypatch: pytest.MonkeyPatch) -> None:
    app = _app()
    published: list[dict] = []

    async def fake_publish(event):
        published.append({"type": event.type, "payload": event.payload})

    class FakeBus:
        async def publish(self, event):
            await fake_publish(event)

    monkeypatch.setattr("urban_hs.ui.tui.app.get_event_bus", lambda: FakeBus())
    app._publish_attack("wifi_deauth", {"count": 10})
    assert len(published) == 1
    assert published[0]["payload"]["type"] == "wifi_deauth"
```

### 4. Testar composição do modal de confirmação (estático)

Chame `compose()` e inspeccione os widgets produzidos:

```python
def test_tui_confirm_modal_composes() -> None:
    app = TUIApp()
    widgets = list(app.compose())
    app._confirm("Run attack?", lambda: None)
    modal = [w for w in app._nodes if hasattr(w, "id") and w.id == "modal-confirm"]
    assert len(modal) == 1
```

---

## Integração com CI

Adicione os smoke tests da TUI à matriz de CI em `.github/workflows/ci.yml`:

```yaml
- name: TUI smoke tests
  run: pytest tests/test_tui_phase10.py -q
```

Testes de TUI em ecrã inteiro (`app.run()`) devem permanecer apenas manuais. Não tente executar Textual em modo headless em CI sem um display virtual (xvfb). Se validação headless for necessária, use `textual run --headless` com comparação de snapshot gravado.

---

## Resolução de problemas em testes custom

- **`ScreenStackError: No screens on stack`** — `query_one` foi chamado antes de `compose()`/`on_mount()`. Use monkeypatch como mostrado acima.
- **`AttributeError: 'FunctionType' object has no attribute 'compose'** — fixture do pytest devolveu a função wrapper, não a instância. Instancie `TUIApp()` directamente no teste.
- **Erros de linter em `TestClient`** — importe de `fastapi.testclient`, não de `fastapi`.
