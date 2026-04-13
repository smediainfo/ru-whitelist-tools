#!/usr/bin/env python3
"""
scan.py — проверяет Selectel /24 сети через TLS handshake с SNI=max.ru.
Работает на macOS python3 из коробки.

Запуск:
  curl -sL https://raw.githubusercontent.com/smediainfo/ru-whitelist-tools/main/scan.py | python3
"""
import socket
import ssl
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

SNI = "max.ru"
TIMEOUT = 4
PARALLEL = 30
SUBNETS = ["80.93.187", "84.38.185"]


def check(ip):
    """Return (ip, status, cert_cn)"""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = socket.create_connection((ip, 443), timeout=TIMEOUT)
        try:
            ssock = ctx.wrap_socket(sock, server_hostname=SNI)
            cert = ssock.getpeercert(binary_form=True)
            # Parse CN from cert — use subprocess openssl to decode
            try:
                import subprocess
                proc = subprocess.run(
                    ["openssl", "x509", "-inform", "DER", "-noout", "-subject"],
                    input=cert, capture_output=True, timeout=3,
                )
                subj = proc.stdout.decode("utf-8", "ignore").strip()
                cn = subj.replace("subject=", "").replace("subject:", "").strip()
                cn = cn[:60]
            except Exception:
                cn = "tls_ok"
            ssock.close()
            return (ip, "OK", cn)
        except ssl.SSLError as e:
            sock.close()
            return (ip, "TLS_FAIL", str(e)[:40])
        except Exception as e:
            try:
                sock.close()
            except Exception:
                pass
            return (ip, "TLS_FAIL", str(e)[:40])
    except socket.timeout:
        return (ip, "BLOCK", "timeout (TSPU?)")
    except ConnectionRefusedError:
        return (ip, "DEAD", "refused")
    except ConnectionResetError:
        return (ip, "BLOCK", "reset (TSPU)")
    except OSError as e:
        return (ip, "BLOCK", f"err: {e}"[:40])


def main():
    print("=" * 50)
    print(f"scan.py — Selectel whitelist checker")
    print(f"Python:  {sys.version.split()[0]}")
    print(f"Subnets: {', '.join(SUBNETS)}")
    print(f"SNI:     {SNI}")
    print(f"Timeout: {TIMEOUT}s, Parallel: {PARALLEL}")
    print("=" * 50)

    # Outgoing IP
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/8"})
        with urllib.request.urlopen(req, timeout=5) as r:
            my_ip = r.read().decode().strip()
    except Exception as e:
        my_ip = f"UNKNOWN ({e})"
    print(f"Outgoing IP: {my_ip}")
    print()
    print("Результаты (live):")
    print()

    ips = [f"{prefix}.{i}" for prefix in SUBNETS for i in range(1, 255)]
    total = len(ips)

    ok = []
    interesting = []
    block = 0
    dead = 0

    with ThreadPoolExecutor(max_workers=PARALLEL) as pool:
        futures = {pool.submit(check, ip): ip for ip in ips}
        for i, future in enumerate(as_completed(futures), 1):
            ip, status, info = future.result()
            if status == "OK":
                print(f"  OK    {ip:<15}  {info}")
                ok.append((ip, info))
                for kw in ("rutube", "yandex", "vk", "mail", "gosuslugi", "selsup", "max.ru", "sbrf", "sberbank"):
                    if kw.lower() in info.lower():
                        interesting.append((ip, info))
                        break
            elif status == "DEAD":
                dead += 1
            else:
                block += 1
            # Progress every 50
            if i % 50 == 0:
                print(f"  ... {i}/{total} обработано, OK={len(ok)} BLK={block} DEAD={dead}", file=sys.stderr)

    print()
    print("=" * 50)
    print("ИТОГ:")
    print(f"  OK     (TLS прошёл):    {len(ok)}")
    print(f"  BLOCK  (timeout/reset): {block}")
    print(f"  DEAD   (refused):       {dead}")
    print("=" * 50)

    if ok:
        print()
        print(f"Живые кандидаты ({len(ok)}):")
        for ip, info in sorted(ok):
            print(f"  {ip:<15}  {info}")
        if interesting:
            print()
            print(f"Особо интересные (по именам whitelist-доменов):")
            for ip, info in sorted(set(interesting)):
                print(f"  {ip:<15}  {info}")
    else:
        print()
        print("Нет живых IP — либо весь /24 режет мобила, либо сети мёртвые.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
