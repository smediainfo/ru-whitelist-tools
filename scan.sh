#!/bin/bash
# scan-selectel.sh
# Сканит 80.93.187.0/24 и 84.38.185.0/24 через SNI max.ru.
# Запускать с мобильного интернета (раздача с телефона).
# Работает на macOS (bash 3.2 + LibreSSL) и Linux.

SNI="max.ru"
PARALLEL=20
TIMEOUT=5
SUBNETS="80.93.187 84.38.185"
DEBUG=0

# Простая обработка --debug
for arg in "$@"; do
    [ "$arg" = "--debug" ] && DEBUG=1
done
[ $DEBUG -eq 1 ] && set -x

# Проверка инструментов
for tool in curl openssl; do
    command -v $tool >/dev/null 2>&1 || {
        printf "ERROR: %s не установлен\n" "$tool"
        exit 1
    }
done

printf "=====================================\n"
printf "Scan Selectel (SNI=%s)\n" "$SNI"
printf "=====================================\n"

MY_IP=$(curl -s --max-time 5 https://api.ipify.org 2>/dev/null)
[ -z "$MY_IP" ] && MY_IP="UNKNOWN"
printf "Your outgoing IP: %s\n" "$MY_IP"
printf "Subnets:  %s\n" "$SUBNETS"
printf "Timeout:  %ss per IP\n" "$TIMEOUT"
printf "Parallel: %s\n" "$PARALLEL"
printf "=====================================\n\n"
printf "Результаты (live):\n\n"

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

# probe: bg openssl + watchdog kill (портабельно, без timeout)
probe() {
    IP=$1
    SNI=$2
    TIMEOUT=$3
    OUTTMP="${TMPDIR}/scan_out_$$_${IP//./_}"

    # Запускаем openssl в background
    ( echo "Q" | openssl s_client -connect "$IP:443" -servername "$SNI" </dev/null ) \
        >"$OUTTMP" 2>&1 &
    OSSL_PID=$!

    # Watchdog — убивает через $TIMEOUT секунд
    ( sleep "$TIMEOUT"; kill -9 $OSSL_PID 2>/dev/null ) >/dev/null 2>&1 &
    WD_PID=$!

    wait $OSSL_PID 2>/dev/null
    kill -9 $WD_PID 2>/dev/null
    wait $WD_PID 2>/dev/null

    OUT=$(cat "$OUTTMP" 2>/dev/null)
    rm -f "$OUTTMP"

    # Парсинг результата
    if echo "$OUT" | grep -q "CONNECTED\|SSL handshake has read"; then
        # TLS прошёл, извлечём subject
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

# Простой пул параллельности
i=0
while IFS= read -r IP; do
    probe "$IP" "$SNI" "$TIMEOUT" &
    i=$((i + 1))
    if [ $((i % PARALLEL)) -eq 0 ]; then
        wait
    fi
done < "$IPFILE"
wait

# Итоги
printf "\n=====================================\n"
OK=$(grep -c "^OK " "$RESULT" 2>/dev/null); OK=${OK:-0}
BLK=$(grep -c "^BLOCK " "$RESULT" 2>/dev/null); BLK=${BLK:-0}
DEAD=$(grep -c "^DEAD " "$RESULT" 2>/dev/null); DEAD=${DEAD:-0}

printf "ИТОГ:\n"
printf "  OK     (TLS прошёл):    %s\n" "$OK"
printf "  BLOCK  (timeout/reset): %s\n" "$BLK"
printf "  DEAD   (refused):       %s\n" "$DEAD"
printf "=====================================\n"

if [ "$OK" -gt 0 ]; then
    printf "\nКандидаты на покупку (%s):\n" "$OK"
    grep "^OK " "$RESULT" | sort

    printf "\nОсобо интересные (rutube/yandex/vk/mail/gosuslugi):\n"
    grep -i "rutube\|yandex\|vk\|mail\|cloud\|selsup\|gosuslugi\|sberbank" "$RESULT" \
        | grep "^OK " | sort || printf "  (ничего)\n"
fi

rm -f "$IPFILE" "$RESULT"
printf "\nГотово.\n"
