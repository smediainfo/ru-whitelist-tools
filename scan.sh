#!/bin/bash
# scan-selectel.sh — Selectel whitelist checker
# Запускать с мобильного интернета (раздача с телефона).

# ============================================================
# САМОДИАГНОСТИКА — должна напечатать 5 строк до начала скана.
# Если ты не видишь эти строчки — проблема в bash/файле, не в логике.
# ============================================================
echo "[TEST 1] Hello from bash — скрипт читается"
echo "[TEST 2] Bash version: $BASH_VERSION"
echo "[TEST 3] OS: $(uname -s) $(uname -r)"
echo "[TEST 4] Curl:    $(command -v curl 2>/dev/null || echo 'MISSING')"
echo "[TEST 5] OpenSSL: $(command -v openssl 2>/dev/null || echo 'MISSING')"
echo ""

# Если curl или openssl нет — дальше смысла нет
if ! command -v curl >/dev/null 2>&1; then
    echo "ERROR: curl не установлен. Ставь через brew install curl"
    exit 1
fi
if ! command -v openssl >/dev/null 2>&1; then
    echo "ERROR: openssl не установлен. Ставь через brew install openssl"
    exit 1
fi

# ============================================================
# Настройки
# ============================================================
SNI="max.ru"
PARALLEL=20
TIMEOUT=5
SUBNETS="80.93.187 84.38.185"
DEBUG=0

for arg in "$@"; do
    [ "$arg" = "--debug" ] && DEBUG=1
done
[ $DEBUG -eq 1 ] && set -x

echo "====================================="
echo "Scan Selectel (SNI=$SNI)"
echo "====================================="

MY_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)
[ -z "$MY_IP" ] && MY_IP="UNKNOWN (api.ipify.org не ответил)"
echo "Your outgoing IP: $MY_IP"
echo "Subnets:  $SUBNETS"
echo "Timeout:  ${TIMEOUT}s per IP"
echo "Parallel: $PARALLEL"
echo "====================================="
echo ""
echo "Результаты (live):"
echo ""

TMPDIR="${TMPDIR:-/tmp}"
IPFILE="$TMPDIR/scan_ips_$$"
RESULT="$TMPDIR/scan_res_$$"
: > "$IPFILE"
: > "$RESULT"

for PREFIX in $SUBNETS; do
    i=1
    while [ $i -le 254 ]; do
        echo "${PREFIX}.${i}" >> "$IPFILE"
        i=$((i + 1))
    done
done

TOTAL=$(wc -l < "$IPFILE" | tr -d ' ')

probe() {
    IP=$1
    SNI=$2
    TIMEOUT=$3
    OUTTMP="${TMPDIR}/scan_out_$$_${IP//./_}"

    ( echo "Q" | openssl s_client -connect "$IP:443" -servername "$SNI" </dev/null ) \
        >"$OUTTMP" 2>&1 &
    OSSL_PID=$!

    ( sleep "$TIMEOUT"; kill -9 $OSSL_PID 2>/dev/null ) >/dev/null 2>&1 &
    WD_PID=$!

    wait $OSSL_PID 2>/dev/null
    kill -9 $WD_PID 2>/dev/null
    wait $WD_PID 2>/dev/null

    OUT=$(cat "$OUTTMP" 2>/dev/null)
    rm -f "$OUTTMP"

    if echo "$OUT" | grep -q "CONNECTED\|SSL handshake has read"; then
        CERT=$(echo "$OUT" | grep -oE "subject=.*|Subject:.*" | head -1 | cut -c1-80)
        [ -z "$CERT" ] && CERT="tls_ok"
        printf "OK    %-15s  %s\n" "$IP" "$CERT"
        printf "OK %s %s\n" "$IP" "$CERT" >> "$RESULT"
    elif echo "$OUT" | grep -q "Connection refused"; then
        printf "DEAD  %-15s  refused\n" "$IP"
        printf "DEAD %s\n" "$IP" >> "$RESULT"
    elif echo "$OUT" | grep -qE "reset by peer|Connection reset"; then
        printf "BLOCK %-15s  reset (TSPU)\n" "$IP"
        printf "BLOCK %s reset\n" "$IP" >> "$RESULT"
    else
        printf "BLOCK %-15s  timeout/block\n" "$IP"
        printf "BLOCK %s timeout\n" "$IP" >> "$RESULT"
    fi
}

i=0
while IFS= read -r IP; do
    probe "$IP" "$SNI" "$TIMEOUT" &
    i=$((i + 1))
    if [ $((i % PARALLEL)) -eq 0 ]; then
        wait
    fi
done < "$IPFILE"
wait

echo ""
echo "====================================="
OK=$(grep -c "^OK " "$RESULT" 2>/dev/null); OK=${OK:-0}
BLK=$(grep -c "^BLOCK " "$RESULT" 2>/dev/null); BLK=${BLK:-0}
DEAD=$(grep -c "^DEAD " "$RESULT" 2>/dev/null); DEAD=${DEAD:-0}

echo "ИТОГ:"
echo "  OK     (TLS прошёл):    $OK"
echo "  BLOCK  (timeout/reset): $BLK"
echo "  DEAD   (refused):       $DEAD"
echo "====================================="

if [ "$OK" -gt 0 ]; then
    echo ""
    echo "Кандидаты на покупку ($OK):"
    grep "^OK " "$RESULT" | sort

    echo ""
    echo "Интересные (rutube/yandex/vk/mail/cloud):"
    grep -i "rutube\|yandex\|vk\|mail\|cloud\|selsup\|gosuslugi\|sberbank" "$RESULT" \
        | grep "^OK " | sort || echo "  (ничего явно не нашлось)"
fi

rm -f "$IPFILE" "$RESULT"
echo ""
echo "Готово."
