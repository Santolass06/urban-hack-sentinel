# Referência da API REST

URL base: `http://<host>:8000`

Todos os endpoints devolvem JSON salvo indicação em contrário.

---

## Índice

- [Conceitos base](#conceitos-base)
- [Autenticação](#autenticação)
- [Endpoints de sistema](#endpoints-de-sistema)
- [Inventário de módulos](#inventário-de-módulos)
- [Execução de ataques](#execução-de-ataques)
- [Endpoints Wi-Fi](#endpoints-wi-fi)
- [Endpoints Bluetooth](#endpoints-bluetooth)
- [Endpoints de rede](#endpoints-de-rede)
- [Event bus (WebSocket)](#event-bus-websocket)
- [Tratamento de erros](#tratamento-de-erros)
- [Exemplo: módulo custom](#exemplo-módulo-custom)

---

## Conceitos base

Os módulos são descobertos dinamicamente. Cada módulo implementa a interface `UrbanPlugin` e regista-se em `urban_hs.modules`. A API expõe duas superfícies principais:

1. **Inventário** — listar módulos/ataques disponíveis.
2. **Execução** — executar um módulo e consumir os seus eventos de ciclo de vida.

A execução é assíncrona. A API devolve um `job_id` imediatamente; o progresso é transmitido pelo event bus.

### Termos chave

- **Módulo** — Classe plugin que implementa `UrbanPlugin`.
- **Ataque** — Um módulo exposto pela superfície de execução.
- **Job** — Uma instância de execução identificada por `job_id`.
- **Evento** — Mensagem publicada no event bus com `type`, `payload`, `timestamp`, `correlation_id`.

---

## Autenticação

De momento a API não tem autenticação. Para ambientes de produção, coloque o serviço atrás de um proxy reverso (nginx) ou envolva-o com uma camada de auth.

Planeado:
- `Authorization: Bearer *** para `/api/v1/attacks/{name}/execute`.
- mTLS para chamadas inter-serviço.

---

## Endpoints de sistema

### `GET /healthz`

Sondagem de saúde para orquestradores.

Resposta:
```json
{"status":"ok"}
```

### `GET /api/v1/info`

Informação de sistema e arquitectura.

Resposta:
```json
{
  "version": "3.0.0",
  "platform": "Linux",
  "machine": "aarch64",
  "release": "6.12.87+rpt-rpi-2712"
}
```

---

## Inventário de módulos

### `GET /api/v1/modules`

Listar todos os módulos registados (plugins).

Resposta:
```json
{
  "modules": {
    "wifi_scan": "urban_hs.modules.wifi:WiFiScanner",
    "wps_pixie": "urban_hs.modules.wifi:WPSPixieAttack",
    "ble_scan": "urban_hs.modules.ble:FastPairScanner"
  }
}
```

### `GET /api/v1/attacks`

Listar ataques agrupados por categoria (`SCANNER`, `EXPLOIT`, `REPORTER`).

Resposta:
```json
{
  "attacks": [
    {
      "name": "wifi_scan",
      "category": "SCANNER",
      "description": "Scan Wi-Fi passivo/activo",
      "class_path": "urban_hs.modules.wifi:WiFiScanner"
    }
  ]
}
```

---

## Execução de ataques

### `POST /api/v1/attacks/{attack_name}/execute`

Executar um ataque registado.

Parâmetros de path:
- `attack_name` — nome do módulo retornado pelo inventário.

Corpo do pedido:
```json
{
  "params": {
    "interface": "wlan1",
    "duration": 30
  },
  "dry_run": false
}
```

- `params` — parâmetros específicos do módulo. Se o módulo definir um schema de parâmetros, é aplicada validação.
- `dry_run` — se `true`, o módulo executa sem efeitos colaterais (sem subprocesso, sem pacotes enviados).

Respostas:
- `202 Accepted` — execução iniciada.
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "attack": "wifi_scan",
  "status": "queued"
}
```
- `404 Not Found` — nome de ataque desconhecido.
- `422 Unprocessable Entity` — `params` falhou na validação.

### `GET /api/v1/attacks/jobs/{job_id}`

Obter estado do job.

Resposta:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "attack": "wifi_scan",
  "status": "running",
  "created_at": "2026-06-29T21:00:00Z"
}
```

Valores possíveis de `status`: `queued`, `running`, `completed`, `error`.

---

## Endpoints Wi-Fi

### `GET /api/v1/wifi/interfaces`

Listar interfaces Wi-Fi.

Resposta:
```json
{
  "interfaces": [
    {
      "name": "wlan1",
      "mac": "aa:bb:cc:dd:ee:ff",
      "driver": "ath9k_htc",
      "monitor_support": true
    }
  ]
}
```

### `POST /api/v1/wifi/scan`

Colocar um scan Wi-Fi na fila.

Corpo do pedido:
```json
{
  "interface": "wlan1",
  "strategy": "passive_only",
  "duration": 30
}
```

Resposta:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/wifi/jobs/{job_id}`

Obter estado do job de scan Wi-Fi.

Resposta:
```json
{
  "job_id": "...",
  "status": "completed",
  "result": {
    "networks": [
      {
        "bssid": "aa:bb:cc:dd:ee:ff",
        "ssid": "MyNetwork",
        "encryption": "WPA2",
        "signal_dbm": -67,
        "channel": 6
      }
    ]
  }
}
```

---

## Endpoints Bluetooth

### `GET /api/v1/ble/status`

Estado do adaptador BLE.

Resposta:
```json
{
  "adapter": "hci0",
  "available": true,
  "scanning": false
}
```

### `POST /api/v1/ble/scan`

Colocar um scan BLE na fila.

Corpo do pedido:
```json
{
  "duration": 10,
  "filter": "fast_pair"
}
```

- `filter` é opcional; valores suportados: `fast_pair`, `whisperpair`, `all`.

Resposta:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/ble/jobs/{job_id}`

Obter estado do job de scan BLE.

Resposta:
```json
{
  "job_id": "...",
  "status": "completed",
  "result": {
    "devices": [
      {
        "address": "aa:bb:cc:dd:ee:ff",
        "name": "Pixel Buds",
        "rssi": -72,
        "connectable": true
      }
    ]
  }
}
```

---

## Endpoints de rede

### `POST /api/v1/network/scan`

Colocar um scan de rede na fila (nmap).

Corpo do pedido:
```json
{
  "targets": ["192.168.1.0/24"],
  "scan_type": "syn",
  "ports": "1-65535"
}
```

Resposta:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/network/jobs/{job_id}`

Obter estado do job de scan de rede.

Resposta:
```json
{
  "job_id": "...",
  "status": "completed",
  "result": {
    "hosts": [
      {
        "address": "192.168.1.10",
        "status": "up",
        "ports": [
          { "port": 22, "protocol": "tcp", "state": "open", "service": "ssh" }
        ]
      }
    ]
  }
}
```

---

## Event bus (WebSocket)

### `WS /api/v1/events`

Ligar para receber eventos em tempo real.

As mensagens são objetos JSON:
```json
{
  "type": "attack.started",
  "payload": {
    "attack": "wifi_scan",
    "job_id": "550e8400-e29b-41d4-a716-446655440000",
    "params": { "interface": "wlan1" }
  }
}
```

### Referência de eventos

| Tipo de evento | Quando é emitido | Campos do payload |
|----------------|------------------|-------------------|
| `attack.started` | Execução começa | `attack`, `job_id`, `params` |
| `attack.progress` | Heartbeat / atualização | `job_id`, `percent`, `message` |
| `attack.completed` | Execução termina com sucesso | `job_id`, `success`, `result` |
| `attack.error` | Execução falha | `job_id`, `error` |

---

## Tratamento de erros

Códigos de status HTTP:

| Código | Significado |
|--------|-------------|
| `200` | OK |
| `202` | Accepted (execução assíncrona iniciada) |
| `400` | Bad request (JSON malformado) |
| `404` | Not found (ataque, job ou endpoint desconhecido) |
| `422` | Erro de validação (params falharam no schema) |
| `500` | Erro interno do servidor |

Formato da resposta de erro:
```json
{
  "detail": "Mensagem de erro legível",
  "correlation_id": "abc-123"
}
```

---

## Exemplo: módulo custom

Para expor um novo módulo através da API:

1. Implementar `UrbanPlugin` em `src/urban_hs/modules/my_module/plugin.py`.
2. Registá-lo em `src/urban_hs/modules/__init__.py` em `_MODULE_REGISTRY`.
3. Emitir `attack.started`, `attack.progress`, `attack.completed` ou `attack.error` no event bus a partir do plugin.
4. Para inventário/execução básica não são necessárias alterações nos routers; o router genérico em `src/urban_hs/ui/api/routers/attacks.py` trata disso.

Plugin mínimo:

```python
from urban_hs.core.plugins import UrbanPlugin, PluginType
from urban_hs.core.event_bus import Event, get_event_bus

class MyScanner(UrbanPlugin):
    name = "my_scanner"
    plugin_type = PluginType.SCANNER
    description = "Exemplo de scanner"

    async def run(self, **kwargs):
        bus = get_event_bus()
        await bus.publish(Event(
            type="attack.started",
            payload={"attack": self.name, "params": kwargs}
        ))
        # ... trabalho ...
        await bus.publish(Event(
            type="attack.completed",
            payload={"attack": self.name, "success": True, "result": {}}
        ))
```
