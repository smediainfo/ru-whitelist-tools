#!/bin/bash
# Минимальный тест — должен напечатать 5 строк
echo "[1] Hello from bash"
echo "[2] Bash version: $BASH_VERSION"
echo "[3] OS: $(uname -s)"
echo "[4] Script path: $0"
echo "[5] TEST OK — script нормально читается и выполняется"
