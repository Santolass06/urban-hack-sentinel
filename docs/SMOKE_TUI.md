# TUI Smoke Test (manual)

## Environment
- Host: Raspberry Pi 5 com Raspberry Pi OS (Bookworm/Trixie)
- Terminal: `TERM=xterm-256color`
- Python: `.venv` do projecto activado

## Steps
1. `cd /home/andresantos/Desktop/Projects/urban-hack-sentinel`
2. `. .venv/bin/activate`
3. `python -m urban_hs.ui.tui.app` (ou `urban-hs-tui`)
4. Confirmar:
   - Header mostra versão + system info
   - Tab WiFi aparece com botões Scan e Interfaces
   - Tab BLE aparece com botão Scan Fast Pair
   - Tab Network aparece com botão Host Discovery
   - Tab Logs aparece com widget de log vazio
5. Pressionar `Scan` na tab WiFi → log mostra evento
6. Pressionar `q` para sair

## Resultado esperado
- TUI entra sem crash
- Pelo menos uma aba mostra dados reais/eventos (WiFi scan ou BLE scan)
