#!/bin/bash

echo "[*] Starting privileged C program attack scenario..."

# Этап 1: Компиляция
echo "[1] Compiling malicious C program..."
gcc privileged_app.c -o /tmp/malicious_binary

if [ ! -f "/tmp/malicious_binary" ]; then
    echo "[-] ERROR: Compilation failed!"
    exit 1
fi
echo "[+] Binary compiled: /tmp/malicious_binary"

# Этап 2: Попытка эскалации привилегий
echo "[2] Attempting to execute with sudo..."
echo "attackerpass" | sudo -S /tmp/malicious_binary 2>/dev/null

# Проверка результата
if [ $? -eq 0 ]; then
    echo "[+] SUCCESS: Program executed with root privileges!"
else
    echo "[-] FAILED: Could not escalate privileges"
fi

# Этап 3: Cleanup (имитация)
echo "[3] Simulating cleanup..."
rm -f /tmp/malicious_binary
echo "[*] Attack finished. Check logs for artifacts."
