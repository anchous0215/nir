#!/bin/bash

echo "[*] Attempting to compile and run a C program with elevated privileges."

echo "[1] Compiling C source code..."
gcc privileged_app.c -o /tmp/privileged_app

if [ -f "/tmp/privileged_app" ]; then
  echo "[*] SUCCESS: Program compiled to /tmp/privileged_app"
else
  echo "[-] ERROR: Failed to compile."
  exit 1
fi

echo "[2] Attempting to run the program with sudo..."
PASSWORD="attackerpass"

# Пытаемся запустить скомпилированную программу с sudo
echo "$PASSWORD" | sudo -S /tmp/privileged_app

echo "[*] Cleanup..."
rm /tmp/privileged_app

echo "[*] Attack finished."
