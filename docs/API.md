# REST API Reference

Base URL: `http://<host>:8000`

All endpoints return JSON unless stated otherwise.

---

## Table of Contents

- [Core concepts](#core-concepts)
- [Authentication](#authentication)
- [System endpoints](#system-endpoints)
- [Module inventory](#module-inventory)
- [Attack execution](#attack-execution)
- [Wi-Fi endpoints](#wi-fi-endpoints)
- [Bluetooth endpoints](#bluetooth-endpoints)
- [Network endpoints](#network-endpoints)
- [Event bus (WebSocket)](#event-bus-websocket)
- [Error handling](#error-handling)
- [Example: custom module](#example-custom-module)

---

## Core concepts

Modules are discovery-driven. Each module implements the `UrbanPlugin` interface and is registered in `urban_hs.modules`. The API exposes two main surfaces:

1. **Inventory** — list available modules/attacks.
2. **Execution** — run a module and consume its lifecycle events.

Execution is asynchronous. The API returns a `job_id` immediately; progress is streamed through the event bus.

### Key terms

- **Module** — A plugin class implementing `UrbanPlugin`.
- **Attack** — A module exposed through the attack execution surface.
- **Job** — An execution instance identified by `job_id`.
- **Event** — A message published on the event bus with `type`, `payload`, `timestamp`, `correlation_id`.

---

## Authentication

Currently the API is unauthenticated. For production deployments, place the service behind a reverse proxy (nginx) or wrap it with an auth layer.

Planned:
- `Authorization: Bearer <token>` for `/api/v1/attacks/{name}/execute`.
- mTLS for inter-service calls.

---

## System endpoints

### `GET /healthz`

Health probe for orchestrators.

Response:
```json
{"status":"ok"}
```

### `GET /api/v1/info`

System and architecture info.

Response:
```json
{
  "version": "3.0.0",
  "platform": "Linux",
  "machine": "aarch64",
  "release": "6.12.87+rpt-rpi-2712"
}
```

---

## Module inventory

### `GET /api/v1/modules`

List all registered modules (plugins).

Response:
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

List attacks grouped by category (`SCANNER`, `EXPLOIT`, `REPORTER`).

Response:
```json
{
  "attacks": [
    {
      "name": "wifi_scan",
      "category": "SCANNER",
      "description": "Passive/active Wi-Fi scan",
      "class_path": "urban_hs.modules.wifi:WiFiScanner"
    }
  ]
}
```

---

## Attack execution

### `POST /api/v1/attacks/{attack_name}/execute`

Execute a registered attack.

Path params:
- `attack_name` — module name from inventory.

Request body:
```json
{
  "params": {
    "interface": "wlan1",
    "duration": 30
  },
  "dry_run": false
}
```

- `params` — module-specific parameters. If the module defines a parameter schema, validation is applied.
- `dry_run` — if `true`, the module runs without side effects (no subprocess, no packets sent).

Responses:
- `202 Accepted` — execution started.
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "attack": "wifi_scan",
  "status": "queued"
}
```
- `404 Not Found` — unknown attack name.
- `422 Unprocessable Entity` — params failed validation.

### `GET /api/v1/attacks/jobs/{job_id}`

Get job status.

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "attack": "wifi_scan",
  "status": "running",
  "created_at": "2026-06-29T21:00:00Z"
}
```

Possible `status` values: `queued`, `running`, `completed`, `error`.

---

## Wi-Fi endpoints

### `GET /api/v1/wifi/interfaces`

List Wi-Fi interfaces.

Response:
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

Queue a Wi-Fi scan.

Request body:
```json
{
  "interface": "wlan1",
  "strategy": "passive_only",
  "duration": 30
}
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/wifi/jobs/{job_id}`

Get Wi-Fi scan job status.

Response:
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

## Bluetooth endpoints

### `GET /api/v1/ble/status`

BLE adapter status.

Response:
```json
{
  "adapter": "hci0",
  "available": true,
  "scanning": false
}
```

### `POST /api/v1/ble/scan`

Queue a BLE scan.

Request body:
```json
{
  "duration": 10,
  "filter": "fast_pair"
}
```

- `filter` is optional; supported values: `fast_pair`, `whisperpair`, `all`.

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/ble/jobs/{job_id}`

Get BLE scan job status.

Response:
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

## Network endpoints

### `POST /api/v1/network/scan`

Queue a network scan (nmap).

Request body:
```json
{
  "targets": ["192.168.1.0/24"],
  "scan_type": "syn",
  "ports": "1-65535"
}
```

Response:
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

### `GET /api/v1/network/jobs/{job_id}`

Get network scan job status.

Response:
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

Connect to receive real-time events.

Messages are JSON objects:
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

### Event reference

| Event type | When emitted | Payload fields |
|------------|--------------|----------------|
| `attack.started` | Execution begins | `attack`, `job_id`, `params` |
| `attack.progress` | Heartbeat / progress update | `job_id`, `percent`, `message` |
| `attack.completed` | Execution finishes successfully | `job_id`, `success`, `result` |
| `attack.error` | Execution fails | `job_id`, `error` |

---

## Error handling

HTTP status codes:

| Code | Meaning |
|------|---------|
| `200` | OK |
| `202` | Accepted (async execution started) |
| `400` | Bad request (malformed JSON) |
| `404` | Not found (unknown attack, job, or endpoint) |
| `422` | Validation error (params failed schema check) |
| `500` | Internal server error |

Error response shape:
```json
{
  "detail": "Human-readable error message",
  "correlation_id": "abc-123"
}
```

---

## Example: custom module

To expose a new module through the API:

1. Implement `UrbanPlugin` in `src/urban_hs/modules/my_module/plugin.py`.
2. Register it in `src/urban_hs/modules/__init__.py` under `_MODULE_REGISTRY`.
3. Emit `attack.started`, `attack.progress`, `attack.completed`, or `attack.error` on the event bus from your plugin.
4. No API router changes are required for basic inventory/execution; the generic router in `src/urban_hs/ui/api/routers/attacks.py` handles it.

Minimal plugin:

```python
from urban_hs.core.plugins import UrbanPlugin, PluginType

class MyScanner(UrbanPlugin):
    name = "my_scanner"
    plugin_type = PluginType.SCANNER
    description = "Example scanner"

    async def run(self, **kwargs):
        from urban_hs.core import get_event_bus
        bus = get_event_bus()
        await bus.publish(Event(
            type="attack.started",
            payload={"attack": self.name, "params": kwargs}
        ))
        # ... do work ...
        await bus.publish(Event(
            type="attack.completed",
            payload={"attack": self.name, "success": True, "result": {}}
        ))
```
