#!/bin/bash
INTERFACE=${INTERFACE:-eth0}
echo "[*] Starting packet capture on interface: $INTERFACE"
# Захватываем 10 пакетов и выводим в лог
tcpdump -c 10 -i $INTERFACE -nn
echo "[*] Packet capture finished."
