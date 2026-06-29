# REST API Reference

Base URL: `http://<host>:8000`

All endpoints return JSON.

## System

### `GET /healthz`
Health probe.

```json
{"status":"ok"}
```

### `GET /api/v1/info`
System + architecture info.

```json
{
  "version": "3.0.0",
  "platform": "Linux",
  "machine": "aarch64",
  "release": "6.12.87+rpt-rpi-2712"
}
```

## Wireless

### `POST /api/v1/wifi/scan`
Queue a WiFi scan.

Request body: JSON
Response: job payload (see `/api/v1/jobs/{id}` when implemented).

## Bluetooth

### `POST /api/v1/ble/scan`
Queue a BLE scan.

## Network

### `POST /api/v1/network/scan`
Queue a network scan.

Empty body is valid.

## Events

### `GET /api/v1/events`
WebSocket endpoint. Use a WebSocket client and open `/api/v1/events`.

Server publishes bus events as JSON messages:
```json
{"type":"event.type","payload":{}}
```

## Web UI

- `GET /` redirects to `/static/index.html`
- `GET /static/index.html` serves the interactive UI
