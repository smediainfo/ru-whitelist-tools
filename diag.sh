#!/bin/bash
# diag.sh — диагностика окружения перед scan-selectel
# Usage: curl -sL https://s.kfk.net/diag | bash

printf "=========================================\n"
printf "ДИАГНОСТИКА\n"
printf "=========================================\n"

printf "\n[1] Окружение\n"
printf "    OS:       %s\n" "$(uname -s)"
printf "    Kernel:   %s\n" "$(uname -r)"
printf "    Bash:     %s\n" "${BASH_VERSION:-unknown}"
printf "    OpenSSL:  %s\n" "$(openssl version 2>&1)"
printf "    Curl:     %s\n" "$(curl --version 2>&1 | head -1)"

printf "\n[2] Инструменты\n"
for tool in curl openssl grep awk sed printf; do
    P=$(command -v $tool 2>/dev/null)
    if [ -n "$P" ]; then
        printf "    %-10s OK  %s\n" "$tool" "$P"
    else
        printf "    %-10s MISSING\n" "$tool"
    fi
done

printf "\n[3] Outgoing IP (должен быть мобильным)\n"
MY_IP=$(curl -sS --max-time 8 https://api.ipify.org 2>&1)
if [ $? -eq 0 ] && [ -n "$MY_IP" ]; then
    printf "    %s\n" "$MY_IP"
    case "$MY_IP" in
        192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*)
            printf "    !!! Приватный — не пошло в интернет\n" ;;
    esac
else
    printf "    FAIL: %s\n" "$MY_IP"
fi

printf "\n[4] Доступ к s.kfk.net/scan\n"
HEAD=$(curl -sS -I --max-time 8 https://s.kfk.net/scan 2>&1)
if [ $? -eq 0 ]; then
    CODE=$(echo "$HEAD" | head -1 | awk '{print $2}')
    SIZE=$(echo "$HEAD" | grep -i "content-length" | awk '{print $2}' | tr -d '\r')
    printf "    HTTP: %s  size: %s bytes\n" "$CODE" "$SIZE"
else
    printf "    FAIL: %s\n" "$HEAD"
fi

printf "\n[5] TLS тест — известно-рабочий Selectel IP (5.188.141.143)\n"
OUTTMP=/tmp/diag_tls_$$
( echo "Q" | openssl s_client -connect 5.188.141.143:443 -servername max.ru </dev/null ) >"$OUTTMP" 2>&1 &
PID=$!
( sleep 8; kill -9 $PID 2>/dev/null ) >/dev/null 2>&1 &
WD=$!
wait $PID 2>/dev/null
kill -9 $WD 2>/dev/null
wait $WD 2>/dev/null
OUT=$(cat "$OUTTMP"); rm -f "$OUTTMP"
if echo "$OUT" | grep -q "CONNECTED\|SSL handshake has read"; then
    SUBJ=$(echo "$OUT" | grep -oE "subject=.*|Subject:.*" | head -1 | cut -c1-80)
    printf "    OK  %s\n" "$SUBJ"
    printf "    → Твой мобильный пропускает SNI=max.ru\n"
else
    printf "    FAIL — режется либо мобила не работает\n"
    echo "$OUT" | head -8 | sed 's/^/      /'
fi

printf "\n[6] TLS тест — 84.38.185.193 (rutube сосед)\n"
OUTTMP=/tmp/diag_tls2_$$
( echo "Q" | openssl s_client -connect 84.38.185.193:443 -servername max.ru </dev/null ) >"$OUTTMP" 2>&1 &
PID=$!
( sleep 8; kill -9 $PID 2>/dev/null ) >/dev/null 2>&1 &
WD=$!
wait $PID 2>/dev/null
kill -9 $WD 2>/dev/null
wait $WD 2>/dev/null
OUT=$(cat "$OUTTMP"); rm -f "$OUTTMP"
if echo "$OUT" | grep -q "CONNECTED\|SSL handshake has read"; then
    SUBJ=$(echo "$OUT" | grep -oE "subject=.*|Subject:.*" | head -1 | cut -c1-80)
    printf "    OK  %s\n" "$SUBJ"
else
    printf "    FAIL — этот IP режется у твоего оператора\n"
    echo "$OUT" | head -5 | sed 's/^/      /'
fi

printf "\n=========================================\n"
printf "Готово. Присылай вывод целиком.\n"
printf "=========================================\n"
