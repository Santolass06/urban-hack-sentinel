#!/usr/bin/env bash
# Quick validation script

echo "=== Urban Hack Sentinel - Setup Validation ==="
echo

# 1. Check tools
echo "1. Verificando ferramentas..."
for tool in aircrack-ng airodump-ng aireplay-ng hcxdumptool hcxpcapngtool reaver bully macchanger iw jq; do
    if command -v "$tool" >/dev/null; then
        echo "   ✓ $tool: $(which $tool)"
    else
        echo "   ✗ $tool: NÃO ENCONTRADO"
    fi
done

# 2. Check capabilities
echo
echo "2. Verificando capabilities..."
for tool in airodump-ng aireplay-ng aircrack-ng hcxdumptool hcxpcapngtool; do
    path=$(which "$tool" 2>/dev/null)
    if [[ -n "$path" ]]; then
        caps=$(getcap "$path" 2>/dev/null || echo "none")
        if [[ "$caps" == *"cap_net_admin"* && "$caps" == *"cap_net_raw"* ]]; then
            echo "   ✓ $tool: $caps"
        else
            echo "   ⚠ $tool: $caps (pode precisar de setcap)"
        fi
    fi
done

# 3. Check config
echo
echo "3. Verificando configuração..."
CONFIG="${CONFIG_FILE:-/etc/urban-hack-sentinel/config.env}"
if [[ -f "$CONFIG" ]]; then
    echo "   ✓ Config: $CONFIG"
    source "$CONFIG"
    echo "      WIFI_IFACE=$WIFI_IFACE"
    echo "      TEMP_LIMIT=$TEMP_LIMIT"
    echo "      MAX_JOBS=$MAX_JOBS"
    echo "      TIMEOUT_SCAN=$TIMEOUT_SCAN"
else
    echo "   ✗ Config não encontrada em $CONFIG"
    echo "      Copia config.env.example para lá"
fi

# 4. Check directories
echo
echo "4. Verificando diretórios..."
for dir in "/var/log/urban-hack-sentinel" "/var/lib/urban-hack-sentinel/hashes" "/var/lib/urban-hack-sentinel/pcaps"; do
    if [[ -d "$dir" ]]; then
        echo "   ✓ $dir"
    else
        echo "   ✗ $dir (falta)"
    fi
done

# 5. Check interface
echo
echo "5. Verificando interface Wi-Fi..."
if [[ -n "${WIFI_IFACE:-}" ]]; then
    if iw dev "$WIFI_IFACE" info >/dev/null 2>&1; then
        echo "   ✓ Interface $WIFI_IFACE existe"
        iw dev "$WIFI_IFACE" info | grep -E 'type|channel|addr'
        # Test monitor mode
        if iw dev "$WIFI_IFACE" info | grep -q "type monitor"; then
            echo "   ✓ Já em modo monitor"
        else
            echo "   ⚠ Não está em modo monitor (script faz isso automaticamente)"
        fi
    else
        echo "   ✗ Interface $WIFI_IFACE não encontrada"
        echo "   Interfaces disponíveis:"
        iw dev | grep -E 'Interface|addr'
    fi
else
    echo "   ⚠ WIFI_IFACE não definido no config"
fi

# 6. Thermal zone
echo
echo "6. Verificando zona térmica..."
if [[ -f /sys/class/thermal/thermal_zone0/temp ]]; then
    temp=$(cat /sys/class/thermal/thermal_zone0/temp)
    echo "   ✓ Thermal zone: $((temp/1000))°C"
else
    echo "   ✗ Thermal zone não encontrada"
fi

# 7. Script syntax
echo
echo "7. Verificando sintaxe do script..."
if bash -n /usr/local/bin/urban-hack-sentinel.sh 2>/dev/null || bash -n "$(pwd)/urban_hack_sentinel.sh"; then
    echo "   ✓ Syntax OK"
else
    echo "   ✗ Syntax ERROR"
fi

echo
echo "=== Fim da validação ==="
