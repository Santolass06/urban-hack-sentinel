# Fluxos de Trabalho do Operador

Como usar o Urban Hack Sentinel em operações reais — desde um scan simples até uma sessão de wardrive com ataques em paralelo.

---

## 1. Pré-requisitos

- Raspberry Pi 5 ou anfitrião x86/64 com Docker instalado.
- Adaptador WiFi Alfa AWUS036ACH (ou outro suportado) em modo monitor.
- Opcional: GPS USB u-blox, adaptador Bluetooth, segunda rádio WiFi.
- Acesso à TUI (`urban-hs-tui`) ou Web UI (`urban-hs-server`).

---

## 2. Fluxo Básico (Ataque Único)

1. Arrancar o *backend*:
   ```bash
   docker compose up -d
   ```
2. Abrir a TUI ou a Web UI.
3. Ir ao separador **WiFi** e executar **Scan**.
4. Esperar que a lista de redes populasse.
5. Seleccionar uma rede alvo e escolher um ataque (ex.: PMKID, Handshake, WPS).
6. Confirmar no modal.
7. Acompanhar o *output* no terminal *live*.
8. Quando terminar, ir a **Exports** para descarregar `.pcapng`, `.22000` ou relatórios.

---

## 3. Modo Wardrive (GPS)

1. Ligar o GPS u-blox e garantir que o `gpsd` está a correr.
2. Na TUI/Web UI, activar o **Modo Wardrive**.
3. O sistema faz um scan passivo contínuo enquanto regista coordenadas GPS.
4. Caminhar ou conduzir pela área alvo.
5. Parar a sessão — o sistema auto-exporta:
   - KML (Google Earth)
   - CSV WiGLE
   - NetXML Kismet
   - JSONL (formato interno de auditoria)

---

## 4. Ataques em Paralelo

1. Iniciar um **scan WiFi** num separador.
2. Simultaneamente iniciar um **scan BLE Fast Pair** noutro separador.
3. Ambos os *feeds* aparecem no mesmo terminal *live*, normalizados pelo *event bus* (`attack.started`, `attack.progress`, `attack.completed`).
4. Podem correr até N ataques em paralelo (limitados pelo gestor de processos e pelos limites de recursos da HAL).
5. Cada ataque tem o seu próprio `job_id` e pode ser cancelado independentemente.

---

## 5. Pós-Operação

1. Revisar o separador **Histórico** com todos os jobs executados.
2. Exportar a sessão completa como relatório PDF/HTML/JSON.
3. Assinar os artefactos com GPG (se activado) para preservar a cadeia de custódia.
4. Importar *handshakes* para o Hashcat ou fazer *upload* do CSV para a WiGLE.

---

## 6. Problemas Comuns

| Sintoma | Causa | Solução |
|---------|-------|---------|
| Scan devolve vazio | Interface não está em modo monitor | Executar `urban-hs config set wifi.interface <iface>` e reiniciar |
| Sem GPS fix | `gpsd` não está a correr ou GPS USB não é detectado | `sudo systemctl start gpsd`; verificar com `gpsmon` |
| Ataque bloqueado | Alvo fora de alcance ou interface ocupada | Cancelar e repetir com alvo mais próximo |
| Web UI não carrega | Backend inacessível | Verificar logs do `urban-hs-server`; porta 8000 aberta |
